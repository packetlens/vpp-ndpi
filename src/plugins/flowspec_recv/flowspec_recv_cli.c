/*
 * flowspec_recv_cli.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec_recv_cli.c - vppctl commands for vpp-flowspec-recv.
 *
 * Commands:
 *   set flowspec-recv socket <path>
 *   set flowspec-recv enable interface <ifname>
 *   set flowspec-recv disable interface <ifname>
 *   show flowspec-recv rules
 *   show flowspec-recv status
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/format.h>
#include <flowspec_recv/flowspec_recv.h>

/* ---------- set flowspec-recv socket ---------- */

static clib_error_t *
set_flowspec_recv_socket_fn (vlib_main_t *vm, unformat_input_t *input,
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

  flowspec_recv_set_socket_path ((const char *) path);
  vlib_cli_output (vm, "flowspec-recv: socket set to %s", path);
  vec_free (path);
  return 0;
}

VLIB_CLI_COMMAND (set_flowspec_recv_socket_cmd, static) = {
  .path = "set flowspec-recv socket",
  .short_help = "set flowspec-recv socket <path>",
  .function = set_flowspec_recv_socket_fn,
};

/* ---------- set flowspec-recv enable/disable interface ---------- */

static clib_error_t *
set_flowspec_recv_interface_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable interface %U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	enable = 1;
      else if (unformat (input, "disable interface %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	enable = 0;
      else if (unformat (input, "interface %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	enable = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0u)
    return clib_error_return (0, "interface required");

  int rv = flowspec_recv_enable_disable_interface (sw_if_index, enable);
  if (rv)
    return clib_error_return (0, "failed to %s flowspec-recv on interface: %d",
			      enable ? "enable" : "disable", rv);

  vlib_cli_output (vm, "flowspec-recv: %s on %U",
		   enable ? "enabled" : "disabled",
		   format_vnet_sw_if_index_name, vnm, sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (set_flowspec_recv_iface_cmd, static) = {
  .path = "set flowspec-recv",
  .short_help =
    "set flowspec-recv (enable|disable) interface <ifname>",
  .function = set_flowspec_recv_interface_fn,
};

/* ---------- show flowspec-recv rules ---------- */

static clib_error_t *
show_flowspec_recv_rules_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  flowspec_recv_main_t *fm = &flowspec_recv_main;

  const char *sock_path =
    fm->sock_path ? (const char *) fm->sock_path : "(not set)";
  const char *state = (fm->sock_fd >= 0) ? "connected" : "not connected";
  vlib_cli_output (vm, "FlowSpec-Recv: socket %s (%s)\n", sock_path, state);

  u32 n_active = 0;
  flowspec_recv_rule_t *r;
  vec_foreach (r, fm->rules)
    if (r->valid)
      n_active++;

  if (n_active == 0)
    {
      vlib_cli_output (vm, "  No active rules.\n");
      goto counters;
    }

  vlib_cli_output (vm, "%-20s %-8s %-12s %-14s %s",
		   "Destination", "Prefix", "Action", "Rate", "Rule ID");
  vlib_cli_output (vm, "%-20s %-8s %-12s %-14s %s",
		   "--------------------", "--------",
		   "------------", "--------------",
		   "------------------------------------");

  vec_foreach (r, fm->rules)
    {
      if (!r->valid)
	continue;

      char rate_str[24] = "—";
      if (r->action == FLOWSPEC_RECV_ACTION_RATE_LIMIT && r->rate_bps > 0)
	{
	  if (r->rate_bps >= 1000000)
	    snprintf (rate_str, sizeof (rate_str), "%.1f Mbps",
		     (f64) r->rate_bps / 1000000.0);
	  else if (r->rate_bps >= 1000)
	    snprintf (rate_str, sizeof (rate_str), "%.1f Kbps",
		     (f64) r->rate_bps / 1000.0);
	  else
	    snprintf (rate_str, sizeof (rate_str), "%llu bps",
		     (unsigned long long) r->rate_bps);
	}

      vlib_cli_output (vm, "%-20U %-8u %-12s %-14s %.36s",
		       format_ip4_address, &r->dst,
		       (unsigned) r->prefix_len,
		       (r->action == FLOWSPEC_RECV_ACTION_RATE_LIMIT)
			 ? "rate-limit" : "drop",
		       rate_str,
		       (char *) r->rule_id);
    }

counters:
  vlib_cli_output (vm,
		   "\nrules active: %u   installed: %llu   removed: %llu   "
		   "socket errors: %llu\n"
		   "pkts dropped: %llu   pkts rate-limited: %llu",
		   n_active,
		   (unsigned long long) fm->rules_installed,
		   (unsigned long long) fm->rules_removed,
		   (unsigned long long) fm->socket_errors,
		   (unsigned long long) fm->pkts_dropped,
		   (unsigned long long) fm->pkts_rate_limited);
  return 0;
}

VLIB_CLI_COMMAND (show_flowspec_recv_rules_cmd, static) = {
  .path = "show flowspec-recv rules",
  .short_help = "show flowspec-recv rules",
  .function = show_flowspec_recv_rules_fn,
};

/* ---------- show flowspec-recv status (alias) ---------- */

static clib_error_t *
show_flowspec_recv_status_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  return show_flowspec_recv_rules_fn (vm, input, cmd);
}

VLIB_CLI_COMMAND (show_flowspec_recv_status_cmd, static) = {
  .path = "show flowspec-recv status",
  .short_help = "show flowspec-recv status",
  .function = show_flowspec_recv_status_fn,
};
