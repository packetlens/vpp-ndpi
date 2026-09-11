/*
 * ndpi_stats.c - VPP stats segment integration for vpp-ndpi.
 *
 * Registers per-plugin gauges in the VPP stats segment (/ndpi/...) and
 * updates them every second from a PROCESS node running on the main thread.
 * The Prometheus exporter (vpp-exporter) reads these gauges via the stats
 * socket without touching the data-plane hot path.
 *
 * Stats paths registered:
 *   /ndpi/flows_created        - cumulative flows seen
 *   /ndpi/flows_classified     - flows with a classification verdict
 *   /ndpi/flows_gave_up        - flows timed out before verdict
 *   /ndpi/flows_active         - currently active flows (pool elements)
 *   /ndpi/packets_scanned      - packets sent to nDPI engine
 *   /ndpi/packets_cached       - packets returned from flow cache without re-scan
 *   /ndpi/ndpi_calls           - ndpi_detection_process_packet() calls
 *   /ndpi/app/<Name>/bytes     - bytes attributed to application <Name>
 *   /ndpi/app/<Name>/packets   - packets attributed to application <Name>
 *   /ndpi/app/<Name>/flows     - flows attributed to application <Name>
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <ndpi/ndpi.h>
#include <vlib/stats/stats.h>

/* Sanitise a protocol name for use as a stats-segment path component.
 * Replaces non-alphanumeric chars (spaces, dots, slashes, …) with '_'.
 * Returns the length of the result (0 means "skip this entry"). */
static u32
ndpi_stats_safe_name (const char *src, char *out, u32 out_len)
{
  u32 j = 0;
  for (const char *p = src; *p && j < out_len - 1; p++, j++)
    {
      char c = *p;
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	  (c >= '0' && c <= '9'))
	out[j] = c;
      else
	out[j] = '_';
    }
  out[j] = '\0';
  return j;
}

/*
 * ndpi_stats_init — called from ndpi_init() after all workers are up.
 * Registers every stats-segment gauge we will maintain.
 */
void
ndpi_stats_init (ndpi_main_t *nm)
{
  ndpi_stats_seg_t *ss = &nm->stats_seg;

  /* Global scalar gauges */
  ss->flows_created    = vlib_stats_add_gauge ("/ndpi/flows_created");
  ss->flows_classified = vlib_stats_add_gauge ("/ndpi/flows_classified");
  ss->flows_gave_up    = vlib_stats_add_gauge ("/ndpi/flows_gave_up");
  ss->flows_active     = vlib_stats_add_gauge ("/ndpi/flows_active");
  ss->packets_scanned  = vlib_stats_add_gauge ("/ndpi/packets_scanned");
  ss->packets_cached   = vlib_stats_add_gauge ("/ndpi/packets_cached");
  ss->ndpi_calls       = vlib_stats_add_gauge ("/ndpi/ndpi_calls");

  /* Per-app gauges: iterate all protocol IDs using worker 0's nDPI engine */
  if (vec_len (nm->per_worker) == 0)
    return;

  ndpi_per_worker_t *pw0 = vec_elt_at_index (nm->per_worker, 0);
  if (!pw0->ndpi)
    return;

  vec_validate_init_empty (ss->app_bytes, NDPI_MAX_SUPPORTED_PROTOCOLS - 1,
			   STAT_SEGMENT_INDEX_INVALID);
  vec_validate_init_empty (ss->app_packets, NDPI_MAX_SUPPORTED_PROTOCOLS - 1,
			   STAT_SEGMENT_INDEX_INVALID);
  vec_validate_init_empty (ss->app_flows, NDPI_MAX_SUPPORTED_PROTOCOLS - 1,
			   STAT_SEGMENT_INDEX_INVALID);

  for (u32 i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++)
    {
      const char *name = ndpi_app_name_for_id (pw0, i);
      if (!name || name[0] == '\0')
	continue;

      char safe[64];
      u32 slen = ndpi_stats_safe_name (name, safe, sizeof (safe));
      if (slen == 0)
	continue;

      ss->app_bytes[i]   = vlib_stats_add_gauge ("/ndpi/app/%s/bytes",   safe);
      ss->app_packets[i] = vlib_stats_add_gauge ("/ndpi/app/%s/packets", safe);
      ss->app_flows[i]   = vlib_stats_add_gauge ("/ndpi/app/%s/flows",   safe);
    }
}

/* ---------------------------------------------------------------------------
 * ndpi-stats-process: VLIB_NODE_TYPE_PROCESS that wakes every 1 s and pushes
 * aggregated counters to the stats segment.
 * ---------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------
 * ndpi_age_flows — called from the stats process while holding the worker
 * barrier. Walks every per-worker flow pool, expires stale entries, and
 * invokes nm->flow_expire_cb (if set) before freeing each.
 * ---------------------------------------------------------------------------*/
static void
ndpi_age_flows (ndpi_main_t *nm, f64 now)
{
  u32 *to_expire = 0;
  u32 fi;

  for (u32 w = 0; w < vec_len (nm->per_worker); w++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);

      /* Collect expired flow indices (pool_foreach is read-only safe). */
      vec_reset_length (to_expire);
      pool_foreach_index (fi, pw->flows)
	{
	  ndpi_flow_t *flow = pool_elt_at_index (pw->flows, fi);
	  u8 proto = flow->is_ip6 ? flow->key6.proto : flow->key4.proto;
	  f64 timeout = (proto == 6 /* TCP */) ? nm->tcp_idle_timeout
					       : nm->udp_idle_timeout;
	  if ((now - flow->last_seen) > timeout)
	    vec_add1 (to_expire, fi);
	}

      /* Expire collected flows. */
      for (u32 j = 0; j < vec_len (to_expire); j++)
	{
	  ndpi_flow_t *flow = pool_elt_at_index (pw->flows, to_expire[j]);

	  /* Notify consumer (e.g. vpp-ipfix) before freeing. */
	  if (nm->flow_expire_cb)
	    nm->flow_expire_cb (pw, flow, nm->flow_expire_cb_opaque);

	  /* Remove from hash table. */
	  if (!flow->is_ip6)
	    {
	      clib_bihash_kv_16_8_t kv;
	      clib_memcpy (&kv.key, &flow->key4, sizeof (flow->key4));
	      clib_bihash_add_del_16_8 (&pw->flow_ht4, &kv, 0 /* del */);
	    }
	  else
	    {
	      clib_bihash_kv_48_8_t kv;
	      clib_memcpy (&kv.key, &flow->key6, sizeof (flow->key6));
	      clib_bihash_add_del_48_8 (&pw->flow_ht6, &kv, 0 /* del */);
	    }

	  ndpi_flow_entry_free (pw, flow);
	  pool_put (pw->flows, flow);
	}
    }

  vec_free (to_expire);
}

static uword
ndpi_stats_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		    vlib_frame_t *f)
{
  ndpi_main_t *nm = &ndpi_main;
  ndpi_stats_seg_t *ss = &nm->stats_seg;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0 /* seconds */);
      vlib_process_get_events (vm, 0 /* discard event data */);
      f64 now = vlib_time_now (vm);

      u32 n_workers = vec_len (nm->per_worker);

      /* --- Scalar counters: sum across workers (no barrier needed) --- */
      u64 flows_created = 0, flows_classified = 0, flows_gave_up = 0;
      u64 pkts_scanned = 0, pkts_cached = 0, ndpi_calls = 0;

      for (u32 w = 0; w < n_workers; w++)
	{
	  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
	  flows_created    += pw->flows_created;
	  flows_classified += pw->flows_classified;
	  flows_gave_up    += pw->flows_gave_up;
	  pkts_scanned     += pw->packets_scanned;
	  pkts_cached      += pw->packets_cached;
	  ndpi_calls       += pw->ndpi_calls;
	}

      vlib_stats_set_gauge (ss->flows_created,    flows_created);
      vlib_stats_set_gauge (ss->flows_classified, flows_classified);
      vlib_stats_set_gauge (ss->flows_gave_up,    flows_gave_up);
      vlib_stats_set_gauge (ss->packets_scanned,  pkts_scanned);
      vlib_stats_set_gauge (ss->packets_cached,   pkts_cached);
      vlib_stats_set_gauge (ss->ndpi_calls,       ndpi_calls);

      /* --- Per-app counters + active flow count: needs barrier --- */
      u64 app_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS];
      u64 app_pkts[NDPI_MAX_SUPPORTED_PROTOCOLS];
      u64 app_flows_arr[NDPI_MAX_SUPPORTED_PROTOCOLS];
      u64 flows_active = 0;

      clib_memset (app_bytes,     0, sizeof (app_bytes));
      clib_memset (app_pkts,      0, sizeof (app_pkts));
      clib_memset (app_flows_arr, 0, sizeof (app_flows_arr));

      vlib_worker_thread_barrier_sync (vm);

      for (u32 w = 0; w < n_workers; w++)
	{
	  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);

	  flows_active += pool_elts (pw->flows);

	  u32 n_intf = vec_len (pw->app_counters_by_intf);
	  for (u32 intf = 0; intf < n_intf; intf++)
	    {
	      ndpi_app_counters_t *ac =
		vec_elt_at_index (pw->app_counters_by_intf, intf);
	      u32 n_app = vec_len (ac->bytes);
	      u32 lim   = clib_min (n_app, NDPI_MAX_SUPPORTED_PROTOCOLS);
	      for (u32 a = 0; a < lim; a++)
		{
		  app_bytes[a]     += ac->bytes[a];
		  app_pkts[a]      += ac->packets[a];
		  app_flows_arr[a] += ac->flows[a];
		}
	    }
	}

      /* Age out stale flows and notify registered callbacks. */
      ndpi_age_flows (nm, now);

      vlib_worker_thread_barrier_release (vm);

      vlib_stats_set_gauge (ss->flows_active, flows_active);

      /* Push per-app gauges (only for registered protocol IDs) */
      u32 n_app_idx = clib_min (vec_len (ss->app_bytes),
				NDPI_MAX_SUPPORTED_PROTOCOLS);
      for (u32 a = 0; a < n_app_idx; a++)
	{
	  if (ss->app_bytes[a] == STAT_SEGMENT_INDEX_INVALID)
	    continue;
	  vlib_stats_set_gauge (ss->app_bytes[a],   app_bytes[a]);
	  vlib_stats_set_gauge (ss->app_packets[a], app_pkts[a]);
	  vlib_stats_set_gauge (ss->app_flows[a],   app_flows_arr[a]);
	}
    }

  return 0; /* NOTREACHED */
}

VLIB_REGISTER_NODE (ndpi_stats_process_node) = {
  .function = ndpi_stats_process,
  .name     = "ndpi-stats-process",
  .type     = VLIB_NODE_TYPE_PROCESS,
};
