/*
 * ndpi_cli.c - vppctl commands for vpp-ndpi.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <ndpi/ndpi.h>

/* ---------- set interface ndpi enable/disable ---------- */

static clib_error_t *
ndpi_set_interface_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0u)
    return clib_error_return (0, "interface required");

  int rv = ndpi_interface_enable_disable (sw_if_index, enable);
  if (rv)
    return clib_error_return (0, "enable/disable rv=%d", rv);
  return 0;
}

VLIB_CLI_COMMAND (ndpi_set_interface_cmd, static) = {
  .path = "set interface ndpi",
  .short_help = "set interface ndpi <interface> [enable|disable]",
  .function = ndpi_set_interface_cmd_fn,
};

/* ---------- show ndpi version ---------- */

static clib_error_t *
show_ndpi_version_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "vpp-ndpi plugin %s", NDPI_PLUGIN_VERSION);
  vlib_cli_output (vm, "libndpi %s", ndpi_revision ());
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_version_cmd, static) = {
  .path = "show ndpi version",
  .short_help = "show ndpi version",
  .function = show_ndpi_version_fn,
};

/* ---------- show ndpi stats ---------- */

static clib_error_t *
show_ndpi_stats_fn (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  ndpi_main_t *nm = &ndpi_main;
  u64 pkts_cached = 0, pkts_scanned = 0;
  u64 flows_created = 0, flows_classified = 0, flows_gave_up = 0;
  u64 calls = 0;
  u32 workers = vec_len (nm->per_worker);

  for (u32 w = 0; w < workers; w++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
      pkts_cached += pw->packets_cached;
      pkts_scanned += pw->packets_scanned;
      flows_created += pw->flows_created;
      flows_classified += pw->flows_classified;
      flows_gave_up += pw->flows_gave_up;
      calls += pw->ndpi_calls;
    }

  vlib_cli_output (vm, "workers:           %u", workers);
  vlib_cli_output (vm, "flows created:     %llu", flows_created);
  vlib_cli_output (vm, "flows classified:  %llu", flows_classified);
  vlib_cli_output (vm, "flows gave up:     %llu", flows_gave_up);
  vlib_cli_output (vm, "packets cached:    %llu", pkts_cached);
  vlib_cli_output (vm, "packets scanned:   %llu", pkts_scanned);
  vlib_cli_output (vm, "nDPI calls:        %llu", calls);
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_stats_cmd, static) = {
  .path = "show ndpi stats",
  .short_help = "show ndpi stats",
  .function = show_ndpi_stats_fn,
};

/* ---------- show ndpi applications ---------- */

typedef struct
{
  u16 app_id;
  u64 pkts;
  u64 bytes;
  u64 flows;
} ndpi_app_row_t;

static int
ndpi_app_row_cmp (const void *a, const void *b)
{
  const ndpi_app_row_t *ra = a;
  const ndpi_app_row_t *rb = b;
  if (ra->bytes > rb->bytes)
    return -1;
  if (ra->bytes < rb->bytes)
    return 1;
  return 0;
}

static clib_error_t *
show_ndpi_applications_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  ndpi_main_t *nm = &ndpi_main;
  u32 top = 20;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "top %u", &top))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  /* Aggregate across workers and interfaces. */
  u64 pkts[NDPI_MAX_SUPPORTED_PROTOCOLS];
  u64 bytes[NDPI_MAX_SUPPORTED_PROTOCOLS];
  u64 flows[NDPI_MAX_SUPPORTED_PROTOCOLS];
  clib_memset (pkts, 0, sizeof (pkts));
  clib_memset (bytes, 0, sizeof (bytes));
  clib_memset (flows, 0, sizeof (flows));

  vlib_worker_thread_barrier_sync (vm);
  for (u32 w = 0; w < vec_len (nm->per_worker); w++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
      for (u32 i = 0; i < vec_len (pw->app_counters_by_intf); i++)
	{
	  ndpi_app_counters_t *ac =
	    vec_elt_at_index (pw->app_counters_by_intf, i);
	  u32 n = vec_len (ac->packets);
	  if (n > NDPI_MAX_SUPPORTED_PROTOCOLS)
	    n = NDPI_MAX_SUPPORTED_PROTOCOLS;
	  for (u32 a = 0; a < n; a++)
	    {
	      pkts[a] += ac->packets[a];
	      bytes[a] += ac->bytes[a];
	      flows[a] += ac->flows[a];
	    }
	}
    }
  vlib_worker_thread_barrier_release (vm);

  ndpi_app_row_t rows[NDPI_MAX_SUPPORTED_PROTOCOLS];
  u32 nrows = 0;
  u64 total_bytes = 0;
  for (u32 i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++)
    {
      if (bytes[i] == 0 && pkts[i] == 0)
	continue;
      rows[nrows].app_id = i;
      rows[nrows].pkts = pkts[i];
      rows[nrows].bytes = bytes[i];
      rows[nrows].flows = flows[i];
      total_bytes += bytes[i];
      nrows++;
    }

  qsort (rows, nrows, sizeof (ndpi_app_row_t), ndpi_app_row_cmp);

  ndpi_per_worker_t *pw0 =
    vec_len (nm->per_worker) ? vec_elt_at_index (nm->per_worker, 0) : NULL;

  vlib_cli_output (vm, "%-24s %10s %10s %14s %8s", "Application", "Flows",
		   "Packets", "Bytes", "%");
  for (u32 i = 0; i < top && i < nrows; i++)
    {
      const char *name = ndpi_app_name_for_id (pw0, rows[i].app_id);
      f64 pct =
	total_bytes ? (100.0 * (f64) rows[i].bytes / (f64) total_bytes) : 0.0;
      vlib_cli_output (vm, "%-24s %10llu %10llu %14llu %7.1f%%", name,
		       rows[i].flows, rows[i].pkts, rows[i].bytes, pct);
    }

  if (nrows == 0)
    vlib_cli_output (vm, "(no classified traffic yet)");
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_applications_cmd, static) = {
  .path = "show ndpi applications",
  .short_help = "show ndpi applications [top <n>]",
  .function = show_ndpi_applications_fn,
};

/* ---------- show ndpi flows ---------- */

static clib_error_t *
show_ndpi_flows_fn (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  ndpi_main_t *nm = &ndpi_main;
  u32 limit = 20;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "count %u", &limit))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  u32 shown = 0;
  vlib_worker_thread_barrier_sync (vm);

  vlib_cli_output (vm, "%-15s %-15s %-5s %-5s %-5s %-14s %-24s %12s",
		   "Src IP", "Dst IP", "Proto", "SPort", "DPort", "App",
		   "SNI", "Bytes");

  for (u32 w = 0; w < vec_len (nm->per_worker) && shown < limit; w++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
      ndpi_flow_t *f;
      pool_foreach (f, pw->flows)
	{
	  if (shown >= limit)
	    break;
	  if (f->is_ip6)
	    continue; /* v1 show focuses on v4 for readability */
	  const char *name =
	    f->classified ? ndpi_app_name_for_id (pw, f->app_protocol) : "-";
	  vlib_cli_output (
	    vm, "%-15U %-15U %-5u %-5u %-5u %-14s %-24s %12llu",
	    format_ip4_address, &f->key4.src, format_ip4_address, &f->key4.dst,
	    (u32) f->key4.proto, (u32) f->key4.src_port,
	    (u32) f->key4.dst_port, name, f->sni[0] ? (char *) f->sni : "-",
	    f->byte_count);
	  shown++;
	}
    }
  vlib_worker_thread_barrier_release (vm);

  if (shown == 0)
    vlib_cli_output (vm, "(no flows)");
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_flows_cmd, static) = {
  .path = "show ndpi flows",
  .short_help = "show ndpi flows [count <n>]",
  .function = show_ndpi_flows_fn,
};

/* ── Phase 7: show ndpi callback ─────────────────────────────────────────── */

static clib_error_t *
show_ndpi_callback_fn (vlib_main_t *vm, unformat_input_t *input,
                       vlib_cli_command_t *cmd)
{
  ndpi_main_t *nm = &ndpi_main;

  vlib_cli_output (vm, "Classification callback:");
  if (nm->classify_cb)
    vlib_cli_output (vm, "  registered: %s", nm->classify_cb_name);
  else
    vlib_cli_output (vm, "  none registered");

  vlib_cli_output (vm, "  calls: %llu",
                   (unsigned long long) nm->classify_cb_calls);
  return 0;
}

VLIB_CLI_COMMAND (show_ndpi_callback_cmd, static) = {
  .path      = "show ndpi callback",
  .short_help = "show ndpi callback",
  .function  = show_ndpi_callback_fn,
};
