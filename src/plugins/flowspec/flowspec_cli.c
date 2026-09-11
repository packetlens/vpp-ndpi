/*
 * flowspec_cli.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec_cli.c - vppctl commands for vpp-flowspec.
 *
 * Commands:
 *   set flowspec socket <path>
 *   set flowspec threshold app <name> bytes-per-sec <N> action drop [hold <sec>]
 *   set flowspec threshold app <name> bytes-per-sec <N> action rate-limit <bps> [hold <sec>]
 *   clear flowspec threshold app <name>
 *   show flowspec status
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <flowspec/flowspec.h>

/* ---------- set flowspec socket ---------- */

static clib_error_t *
set_flowspec_socket_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  u8 *path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%s", &path))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (!path)
    return clib_error_return (0, "socket path required");

  flowspec_set_socket_path ((const char *) path);
  vlib_cli_output (vm, "flowspec socket set to %s", path);
  vec_free (path);
  return 0;
}

VLIB_CLI_COMMAND (set_flowspec_socket_cmd, static) = {
  .path = "set flowspec socket",
  .short_help = "set flowspec socket <path>",
  .function = set_flowspec_socket_fn,
};

/* ---------- set flowspec threshold ---------- */

static clib_error_t *
set_flowspec_threshold_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;
  u64 bps_threshold = 0;
  u8 action = FLOWSPEC_ACTION_DROP;
  u64 rate_bps = 0;
  u32 hold_sec = FLOWSPEC_DEFAULT_HOLD_SEC;
  int threshold_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "app %s", &app_name))
	;
      else if (unformat (input, "bytes-per-sec %llu", &bps_threshold))
	threshold_set = 1;
      else if (unformat (input, "action drop"))
	action = FLOWSPEC_ACTION_DROP;
      else if (unformat (input, "action rate-limit %llu", &rate_bps))
	action = FLOWSPEC_ACTION_RATE_LIMIT;
      else if (unformat (input, "hold %u", &hold_sec))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (!app_name)
    return clib_error_return (0, "app name required");
  if (!threshold_set)
    return clib_error_return (0, "bytes-per-sec required");
  if (action == FLOWSPEC_ACTION_RATE_LIMIT && rate_bps == 0)
    return clib_error_return (0, "rate-limit requires a bps value");

  int rv = flowspec_threshold_set (app_name, bps_threshold, action,
				   rate_bps, hold_sec);
  if (rv)
    return clib_error_return (0, "flowspec_threshold_set failed: %d", rv);

  const char *action_str = (action == FLOWSPEC_ACTION_RATE_LIMIT)
    ? "rate-limit" : "drop";

  if (action == FLOWSPEC_ACTION_RATE_LIMIT)
    vlib_cli_output (vm, "flowspec: %s threshold %llu B/s → %s %llu bps (hold %us)",
		     app_name, bps_threshold, action_str, rate_bps, hold_sec);
  else
    vlib_cli_output (vm, "flowspec: %s threshold %llu B/s → %s (hold %us)",
		     app_name, bps_threshold, action_str, hold_sec);

  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (set_flowspec_threshold_cmd, static) = {
  .path = "set flowspec threshold",
  .short_help =
    "set flowspec threshold app <name> bytes-per-sec <N> "
    "action (drop | rate-limit <bps>) [hold <sec>]",
  .function = set_flowspec_threshold_fn,
};

/* ---------- clear flowspec threshold ---------- */

static clib_error_t *
clear_flowspec_threshold_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "app %s", &app_name))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (!app_name)
    return clib_error_return (0, "app name required");

  int rv = flowspec_threshold_clear (app_name);
  if (rv)
    vlib_cli_output (vm, "flowspec: app '%s' not found", app_name);
  else
    vlib_cli_output (vm, "flowspec: threshold for '%s' removed", app_name);

  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (clear_flowspec_threshold_cmd, static) = {
  .path = "clear flowspec threshold",
  .short_help = "clear flowspec threshold app <name>",
  .function = clear_flowspec_threshold_fn,
};

/* ---------- show flowspec status ---------- */

static clib_error_t *
show_flowspec_status_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  flowspec_main_t *fm = &flowspec_main;
  ndpi_main_t *nm = &ndpi_main;

  /* Socket status */
  const char *sock_path =
    fm->sock_path ? (const char *) fm->sock_path : "(not set)";
  const char *conn_state = (fm->sock_fd >= 0) ? "connected" : "not connected";
  vlib_cli_output (vm, "FlowSpec notify: socket %s (%s)\n",
		   sock_path, conn_state);

  if (vec_len (fm->thresholds) == 0)
    {
      vlib_cli_output (vm, "  No thresholds configured.\n");
      goto counters;
    }

  /* Get a worker for name lookup */
  ndpi_per_worker_t *pw0 = NULL;
  if (vec_len (nm->per_worker) > 0)
    pw0 = vec_elt_at_index (nm->per_worker, 0);

  /* Header */
  vlib_cli_output (vm, "%-24s %-12s %-10s %-20s %-10s",
		   "App", "Threshold", "Current", "Action", "State");
  vlib_cli_output (vm, "%-24s %-12s %-10s %-20s %-10s",
		   "------------------------",
		   "------------", "----------",
		   "--------------------", "----------");

  /* Current bytes/sec for each threshold app */
  f64 now = vlib_time_now (vm);
  f64 dt = now - fm->prev_poll_time;
  if (dt < 0.001)
    dt = 1.0;

  flowspec_threshold_t *t;
  vec_foreach (t, fm->thresholds)
    {
      /* Current bps estimate */
      f64 cur_bps = 0.0;
      if (t->app_id != (u16) ~0u && t->app_id < NDPI_MAX_SUPPORTED_PROTOCOLS)
	{
	  u64 cur = 0;
	  /* Sum app bytes from all workers under barrier (brief). */
	  vlib_worker_thread_barrier_sync (vm);
	  for (u32 w = 0; w < vec_len (nm->per_worker); w++)
	    {
	      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
	      for (u32 intf = 0; intf < vec_len (pw->app_counters_by_intf);
		   intf++)
		{
		  ndpi_app_counters_t *ac =
		    vec_elt_at_index (pw->app_counters_by_intf, intf);
		  if (t->app_id < vec_len (ac->bytes))
		    cur += ac->bytes[t->app_id];
		}
	    }
	  vlib_worker_thread_barrier_release (vm);

	  if (cur >= fm->prev_app_bytes[t->app_id])
	    cur_bps =
	      (f64) (cur - fm->prev_app_bytes[t->app_id]) / dt;
	}

      /* Format threshold */
      char thresh_str[32];
      if (t->bps_threshold >= 1024 * 1024)
	snprintf (thresh_str, sizeof (thresh_str), "%.0f MB/s",
		  (f64) t->bps_threshold / (1024 * 1024));
      else if (t->bps_threshold >= 1024)
	snprintf (thresh_str, sizeof (thresh_str), "%.0f KB/s",
		  (f64) t->bps_threshold / 1024);
      else
	snprintf (thresh_str, sizeof (thresh_str), "%llu B/s",
		  (unsigned long long) t->bps_threshold);

      /* Format current bps */
      char cur_str[32];
      if (cur_bps >= 1024 * 1024)
	snprintf (cur_str, sizeof (cur_str), "%.1f MB/s",
		  cur_bps / (1024 * 1024));
      else if (cur_bps >= 1024)
	snprintf (cur_str, sizeof (cur_str), "%.1f KB/s", cur_bps / 1024);
      else
	snprintf (cur_str, sizeof (cur_str), "%.0f B/s", cur_bps);

      /* Format action */
      char action_str[32];
      if (t->action == FLOWSPEC_ACTION_RATE_LIMIT)
	snprintf (action_str, sizeof (action_str), "rate-limit %llu bps",
		  (unsigned long long) t->rate_bps);
      else
	snprintf (action_str, sizeof (action_str), "drop");

      /* Format app name with ID (app_name is 64 bytes + " (65535)" = 72 max) */
      char name_str[80];
      if (t->app_id == (u16) ~0u)
	snprintf (name_str, sizeof (name_str), "%s (unresolved)",
		  (char *) t->app_name);
      else
	snprintf (name_str, sizeof (name_str), "%s (%u)",
		  (char *) t->app_name, (unsigned) t->app_id);

      vlib_cli_output (vm, "%-24s %-12s %-10s %-20s %-10s",
		       name_str, thresh_str, cur_str, action_str,
		       t->triggered ? "TRIGGERED" : "normal");
    }

counters:
  vlib_cli_output (vm, "\nevents sent: %llu   socket errors: %llu   "
		   "threshold crossings: %llu",
		   (unsigned long long) fm->events_sent,
		   (unsigned long long) fm->socket_errors,
		   (unsigned long long) fm->threshold_crossings);
  return 0;
}

VLIB_CLI_COMMAND (show_flowspec_status_cmd, static) = {
  .path = "show flowspec status",
  .short_help = "show flowspec status",
  .function = show_flowspec_status_fn,
};
