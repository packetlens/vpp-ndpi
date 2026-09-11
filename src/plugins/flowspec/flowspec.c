/*
 * flowspec.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec.c - vpp-flowspec plugin init and process node.
 *
 * The flowspec-process node wakes every 2 seconds, takes the worker barrier,
 * reads per-app byte counters and collects destination IPs from active flows,
 * then releases the barrier.  It computes bytes/sec deltas and fires
 * announce/withdraw events to the flowspec-ctrl Unix socket whenever an app
 * threshold is crossed.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <flowspec/flowspec.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

flowspec_main_t flowspec_main;

/* ---------------------------------------------------------------------------
 * Socket helpers
 * ---------------------------------------------------------------------------*/

/* Attempt a non-blocking connect to the Unix domain socket.
 * Returns 0 on success (or already connected), -1 on error. */
static int
flowspec_sock_connect (flowspec_main_t *fm)
{
  if (fm->sock_fd >= 0)
    return 0; /* already connected */

  if (!fm->sock_path || fm->sock_path[0] == '\0')
    return -1;

  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un sa;
  clib_memset (&sa, 0, sizeof (sa));
  sa.sun_family = AF_UNIX;
  strncpy (sa.sun_path, (const char *) fm->sock_path, sizeof (sa.sun_path) - 1);

  if (connect (fd, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      close (fd);
      return -1;
    }

  fm->sock_fd = fd;
  vlib_log_info (fm->log_class, "connected to %s", fm->sock_path);
  return 0;
}

/* Send a NUL-terminated JSON line to the socket.  Reconnects on error. */
static void
flowspec_sock_send (flowspec_main_t *fm, const char *json)
{
  if (fm->sock_fd < 0)
    {
      if (flowspec_sock_connect (fm) < 0)
	{
	  fm->socket_errors++;
	  return;
	}
    }

  size_t len = strlen (json);
  ssize_t sent = send (fm->sock_fd, json, len, MSG_NOSIGNAL);
  if (sent < 0)
    {
      vlib_log_warn (fm->log_class, "socket send error: %d — reconnecting",
		     errno);
      close (fm->sock_fd);
      fm->sock_fd = -1;
      fm->socket_errors++;
    }
  else
    {
      fm->events_sent++;
    }
}

/* ---------------------------------------------------------------------------
 * Resolve an app name string to an nDPI protocol ID.
 * Uses the first worker's detection module (all workers share the same
 * protocol table).  Returns ~0u if not found.
 * ---------------------------------------------------------------------------*/
static u16
flowspec_resolve_app_id (const u8 *name)
{
  ndpi_main_t *nm = &ndpi_main;

  if (vec_len (nm->per_worker) == 0)
    return (u16) ~0u; /* workers not yet up */

  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, 0);
  if (!pw->ndpi)
    return (u16) ~0u;

  /* Iterate over all protocol IDs and compare names (case-insensitive). */
  for (u32 i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++)
    {
      const char *proto_name = ndpi_get_proto_name (pw->ndpi, (u16) i);
      if (!proto_name || proto_name[0] == '\0')
	continue;
      if (strcasecmp ((const char *) name, proto_name) == 0)
	return (u16) i;
    }
  return (u16) ~0u;
}

/* ---------------------------------------------------------------------------
 * Build and send an "announce" or "withdraw" JSON event.
 *
 * Announce format (newline-terminated):
 * {"type":"announce","app_id":124,"app_name":"YouTube","action":"rate_limit",
 *  "rate_bps":10000000,"hold_sec":60,
 *  "prefixes":["142.250.185.196/32","172.217.16.100/32"]}
 *
 * Withdraw format:
 * {"type":"withdraw","app_id":124,"app_name":"YouTube"}
 * ---------------------------------------------------------------------------*/
static void
flowspec_send_announce (flowspec_main_t *fm, flowspec_threshold_t *t,
			ip4_address_t *dsts, u8 n_dst)
{
  char buf[4096];
  char *p = buf;
  char *end = buf + sizeof (buf) - 1;

  const char *action_str =
    (t->action == FLOWSPEC_ACTION_RATE_LIMIT) ? "rate_limit" : "drop";

  p += snprintf (p, end - p,
		 "{\"type\":\"announce\",\"app_id\":%u,\"app_name\":\"%s\","
		 "\"action\":\"%s\",\"rate_bps\":%llu,\"hold_sec\":%u,"
		 "\"prefixes\":[",
		 (unsigned) t->app_id, (char *) t->app_name, action_str,
		 (unsigned long long) t->rate_bps, (unsigned) t->hold_sec);

  for (u8 i = 0; i < n_dst && p < end - 24; i++)
    {
      if (i > 0)
	*p++ = ',';
      p += snprintf (p, end - p, "\"%u.%u.%u.%u/32\"",
		     dsts[i].as_u8[0], dsts[i].as_u8[1],
		     dsts[i].as_u8[2], dsts[i].as_u8[3]);
    }

  p += snprintf (p, end - p, "]}\n");

  flowspec_sock_send (fm, buf);
}

static void
flowspec_send_withdraw (flowspec_main_t *fm, flowspec_threshold_t *t)
{
  char buf[256];
  snprintf (buf, sizeof (buf),
	    "{\"type\":\"withdraw\",\"app_id\":%u,\"app_name\":\"%s\"}\n",
	    (unsigned) t->app_id, (char *) t->app_name);
  flowspec_sock_send (fm, buf);
}

/* ---------------------------------------------------------------------------
 * Threshold evaluation.
 *
 * Called after the barrier is released, so it's safe to read prev_app_bytes
 * (main-thread-only data) without locks.
 * ---------------------------------------------------------------------------*/
static void
flowspec_evaluate (flowspec_main_t *fm,
		   u64 *app_bytes,           /* array [NDPI_MAX_SUPPORTED_PROTOCOLS] */
		   ip4_address_t dst_ips[][FLOWSPEC_MAX_DST_PER_APP],
		   u8 *dst_counts,           /* array [NDPI_MAX_SUPPORTED_PROTOCOLS] */
		   f64 now)
{
  f64 dt = now - fm->prev_poll_time;
  if (dt < 0.001)
    dt = 0.001; /* avoid div-by-zero on first call */

  flowspec_threshold_t *t;
  vec_foreach (t, fm->thresholds)
    {
      /* Resolve app_id on first use (workers may not have been up at CLI time). */
      if (t->app_id == (u16) ~0u)
	{
	  t->app_id = flowspec_resolve_app_id (t->app_name);
	  if (t->app_id == (u16) ~0u)
	    continue; /* still unresolved */
	}

      u16 id = t->app_id;
      if (id >= NDPI_MAX_SUPPORTED_PROTOCOLS)
	continue;

      u64 delta_bytes = 0;
      if (app_bytes[id] >= fm->prev_app_bytes[id])
	delta_bytes = app_bytes[id] - fm->prev_app_bytes[id];

      f64 bps = (f64) delta_bytes / dt;

      if (!t->triggered)
	{
	  /* NORMAL → TRIGGERED */
	  if (bps >= (f64) t->bps_threshold)
	    {
	      t->triggered = 1;
	      t->triggered_at = now;
	      fm->threshold_crossings++;

	      vlib_log_info (fm->log_class,
			     "threshold crossed: %s (id=%u) %.0f B/s >= %llu B/s",
			     (char *) t->app_name, id, bps,
			     (unsigned long long) t->bps_threshold);

	      ip4_address_t *dsts = dst_ips[id];
	      flowspec_send_announce (fm, t, dsts, dst_counts[id]);
	    }
	}
      else
	{
	  /* TRIGGERED → NORMAL (hysteresis) */
	  if (bps < (f64) t->bps_threshold * FLOWSPEC_WITHDRAW_HYSTERESIS)
	    {
	      t->triggered = 0;

	      vlib_log_info (fm->log_class,
			     "threshold cleared: %s (id=%u) %.0f B/s",
			     (char *) t->app_name, id, bps);

	      flowspec_send_withdraw (fm, t);
	    }
	}
    }

  /* Snapshot byte counters and time for the next cycle. */
  clib_memcpy (fm->prev_app_bytes, app_bytes,
	       NDPI_MAX_SUPPORTED_PROTOCOLS * sizeof (u64));
  fm->prev_poll_time = now;
}

/* ---------------------------------------------------------------------------
 * flowspec-process — VLIB_NODE_TYPE_PROCESS, wakes every 2 seconds.
 * ---------------------------------------------------------------------------*/
static uword
flowspec_process_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
		     vlib_frame_t *frame)
{
  flowspec_main_t *fm = &flowspec_main;
  ndpi_main_t *nm = &ndpi_main;

  /* Per-app byte totals, accumulated across workers. */
  static u64 app_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS];
  /* Destination IPs collected from flow pool for each threshold app. */
  static ip4_address_t dst_ips[NDPI_MAX_SUPPORTED_PROTOCOLS][FLOWSPEC_MAX_DST_PER_APP];
  static u8 dst_counts[NDPI_MAX_SUPPORTED_PROTOCOLS];

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 2.0 /* seconds */);
      vlib_process_get_events (vm, 0 /* discard */);

      f64 now = vlib_time_now (vm);
      u32 n_workers = vec_len (nm->per_worker);

      if (n_workers == 0 || vec_len (fm->thresholds) == 0)
	continue;

      /* Build a set of app IDs we care about (for fast flow-table filtering). */
      clib_memset (app_bytes, 0, sizeof (app_bytes));
      clib_memset (dst_counts, 0, sizeof (dst_counts));

      /* ── Take worker barrier ─────────────────────────────────────────── */
      vlib_worker_thread_barrier_sync (vm);

      for (u32 w = 0; w < n_workers; w++)
	{
	  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);

	  /* Aggregate app_bytes across all interfaces on this worker. */
	  u32 n_intf = vec_len (pw->app_counters_by_intf);
	  for (u32 intf = 0; intf < n_intf; intf++)
	    {
	      ndpi_app_counters_t *ac =
		vec_elt_at_index (pw->app_counters_by_intf, intf);
	      u32 n_app = clib_min (vec_len (ac->bytes),
				    NDPI_MAX_SUPPORTED_PROTOCOLS);
	      for (u32 a = 0; a < n_app; a++)
		app_bytes[a] += ac->bytes[a];
	    }

	  /* For each threshold with a resolved app_id: collect dst IPs from
	   * active flows.  We limit to FLOWSPEC_MAX_DST_PER_APP per app. */
	  flowspec_threshold_t *t;
	  vec_foreach (t, fm->thresholds)
	    {
	      u16 id = t->app_id;
	      if (id == (u16) ~0u || id >= NDPI_MAX_SUPPORTED_PROTOCOLS)
		continue;
	      if (dst_counts[id] >= FLOWSPEC_MAX_DST_PER_APP)
		continue;

	      ndpi_flow_t *f;
	      pool_foreach (f, pw->flows)
		{
		  if (f->classified && !f->is_ip6 && f->app_protocol == id)
		    {
		      /* Deduplicate: check if already collected. */
		      u8 dup = 0;
		      for (u8 k = 0; k < dst_counts[id]; k++)
			{
			  if (dst_ips[id][k].as_u32 == f->key4.dst.as_u32)
			    {
			      dup = 1;
			      break;
			    }
			}
		      if (!dup && dst_counts[id] < FLOWSPEC_MAX_DST_PER_APP)
			dst_ips[id][dst_counts[id]++] = f->key4.dst;
		    }
		}
	    }
	}

      vlib_worker_thread_barrier_release (vm);
      /* ── Barrier released ────────────────────────────────────────────── */

      /* Evaluate thresholds and send events outside the barrier. */
      flowspec_evaluate (fm, app_bytes, dst_ips, dst_counts, now);
    }

  return 0; /* NOTREACHED */
}

VLIB_REGISTER_NODE (flowspec_process_node) = {
  .function = flowspec_process_fn,
  .name = "flowspec-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

/* ---------------------------------------------------------------------------
 * Public API (called from flowspec_cli.c)
 * ---------------------------------------------------------------------------*/

int
flowspec_set_socket_path (const char *path)
{
  flowspec_main_t *fm = &flowspec_main;

  if (fm->sock_fd >= 0)
    {
      close (fm->sock_fd);
      fm->sock_fd = -1;
    }

  if (fm->sock_path)
    {
      vec_free (fm->sock_path);
      fm->sock_path = 0;
    }

  if (path && path[0])
    {
      u32 len = strlen (path) + 1;
      vec_validate (fm->sock_path, len - 1);
      clib_memcpy (fm->sock_path, path, len);
      fm->sock_path[len - 1] = '\0';
    }

  return 0;
}

int
flowspec_threshold_set (const u8 *app_name, u64 bps_threshold, u8 action,
			u64 rate_bps, u32 hold_sec)
{
  flowspec_main_t *fm = &flowspec_main;

  /* Update existing entry for the same app name. */
  flowspec_threshold_t *t;
  vec_foreach (t, fm->thresholds)
    {
      if (strcasecmp ((const char *) t->app_name, (const char *) app_name) == 0)
	{
	  t->bps_threshold = bps_threshold;
	  t->action = action;
	  t->rate_bps = rate_bps;
	  t->hold_sec = hold_sec;
	  /* Reset state so a new announce is sent if already triggered. */
	  t->triggered = 0;
	  return 0;
	}
    }

  /* New entry. */
  flowspec_threshold_t new_t;
  clib_memset (&new_t, 0, sizeof (new_t));
  strncpy ((char *) new_t.app_name, (const char *) app_name,
	   sizeof (new_t.app_name) - 1);
  new_t.bps_threshold = bps_threshold;
  new_t.action = action;
  new_t.rate_bps = rate_bps;
  new_t.hold_sec = hold_sec ? hold_sec : FLOWSPEC_DEFAULT_HOLD_SEC;
  new_t.triggered = 0;
  /* Attempt to resolve app_id immediately; may be ~0u if workers not yet up. */
  new_t.app_id = flowspec_resolve_app_id (app_name);

  vec_add1 (fm->thresholds, new_t);
  return 0;
}

int
flowspec_threshold_clear (const u8 *app_name)
{
  flowspec_main_t *fm = &flowspec_main;
  u32 i;
  vec_foreach_index (i, fm->thresholds)
    {
      if (strcasecmp ((const char *) fm->thresholds[i].app_name,
		      (const char *) app_name) == 0)
	{
	  /* Send withdraw if currently triggered. */
	  if (fm->thresholds[i].triggered)
	    flowspec_send_withdraw (fm, &fm->thresholds[i]);
	  vec_del1 (fm->thresholds, i);
	  return 0;
	}
    }
  return -1; /* not found */
}

/* ---------------------------------------------------------------------------
 * Plugin init
 * ---------------------------------------------------------------------------*/
static clib_error_t *
flowspec_init (vlib_main_t *vm)
{
  flowspec_main_t *fm = &flowspec_main;
  fm->vlib_main = vm;
  fm->log_class = vlib_log_register_class ("flowspec", 0);
  fm->sock_fd = -1;

  /* Default socket path. */
  const char *dflt = FLOWSPEC_DEFAULT_SOCK_PATH;
  u32 len = strlen (dflt) + 1;
  vec_validate (fm->sock_path, len - 1);
  clib_memcpy (fm->sock_path, dflt, len);

  clib_memset (fm->prev_app_bytes, 0, sizeof (fm->prev_app_bytes));
  fm->prev_poll_time = 0.0;

  vlib_log_info (fm->log_class, "vpp-flowspec %s initialized",
		 FLOWSPEC_PLUGIN_VERSION);
  return 0;
}

/* Must init after ndpi. */
VLIB_INIT_FUNCTION (flowspec_init);
