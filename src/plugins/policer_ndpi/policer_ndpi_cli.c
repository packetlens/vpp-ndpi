/*
 * policer_ndpi_cli.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policer_ndpi_cli.c - vppctl commands for vpp-policer-ndpi.
 *
 * Commands:
 *   set policer-ndpi app <name> rate <kbps> burst <bytes> [action (drop|dscp-mark <val>)]
 *   clear policer-ndpi app <name>
 *   show policer-ndpi
 *   set interface policer-ndpi <interface> (enable|disable)
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <policer_ndpi/policer_ndpi.h>

/* ---------- set policer-ndpi app ---------- */

static clib_error_t *
set_policer_ndpi_app_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;
  u32 rate_kbps = 0;
  u32 burst_bytes = 0;
  u8 exceed_action = POLICER_NDPI_ACTION_DROP;
  u32 dscp_raw = 0; /* parse into u32 to avoid ip_dscp_t overflow */
  int rate_set = 0, burst_set = 0;

  /* CLI path is "set policer-ndpi app"; remaining: "<name> rate ... burst ..." */
  if (!unformat (input, "%s", &app_name))
    return clib_error_return (0, "app name required");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rate %u", &rate_kbps))
	rate_set = 1;
      else if (unformat (input, "burst %u", &burst_bytes))
	burst_set = 1;
      else if (unformat (input, "action drop"))
	exceed_action = POLICER_NDPI_ACTION_DROP;
      else if (unformat (input, "action dscp-mark %u", &dscp_raw))
	exceed_action = POLICER_NDPI_ACTION_DSCP_MARK;
      else
	{
	  vec_free (app_name);
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  if (!rate_set)
    {
      vec_free (app_name);
      return clib_error_return (0, "rate <kbps> required");
    }
  if (!burst_set)
    burst_bytes = rate_kbps * 125; /* default burst = 1s worth of data */

  int rv = policer_ndpi_set_app (app_name, rate_kbps, burst_bytes,
				  exceed_action, (ip_dscp_t) dscp_raw);
  if (rv)
    {
      clib_error_t *e;
      if (rv == -1)
	e = clib_error_return (0,
			       "unknown application '%s' — check nDPI app name",
			       app_name);
      else
	e = clib_error_return (0, "policer_add failed: %d", rv);
      vec_free (app_name);
      return e;
    }

  if (exceed_action == POLICER_NDPI_ACTION_DSCP_MARK)
    vlib_cli_output (vm, "policer-ndpi: %s %u kbps burst %u bytes → dscp-mark %u",
		     app_name, rate_kbps, burst_bytes, (unsigned) dscp_raw);
  else
    vlib_cli_output (vm, "policer-ndpi: %s %u kbps burst %u bytes → drop",
		     app_name, rate_kbps, burst_bytes);
  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (set_policer_ndpi_app_cmd, static) = {
  .path = "set policer-ndpi app",
  .short_help =
    "set policer-ndpi app <name> rate <kbps> burst <bytes> "
    "[action (drop|dscp-mark <val>)]",
  .function = set_policer_ndpi_app_fn,
};

/* ---------- clear policer-ndpi app ---------- */

static clib_error_t *
clear_policer_ndpi_app_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;

  if (!unformat (input, "%s", &app_name))
    return clib_error_return (0, "app name required");

  policer_ndpi_clear_app (app_name);
  vlib_cli_output (vm, "policer-ndpi: policer for '%s' removed", app_name);
  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (clear_policer_ndpi_app_cmd, static) = {
  .path = "clear policer-ndpi app",
  .short_help = "clear policer-ndpi app <name>",
  .function = clear_policer_ndpi_app_fn,
};

/* ---------- show policer-ndpi ---------- */

static clib_error_t *
show_policer_ndpi_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  policer_ndpi_main_t *pm = &policer_ndpi_main;

  if (vec_len (pm->named_policers) == 0)
    {
      vlib_cli_output (vm, "No per-app policers configured.");
      return 0;
    }

  vlib_cli_output (vm, "%-24s %-8s %-12s %-10s %-12s",
		   "Application", "ID", "Rate (kbps)", "Burst (B)",
		   "Exceed");
  vlib_cli_output (vm, "%-24s %-8s %-12s %-10s %-12s",
		   "------------------------", "--------",
		   "------------", "----------", "------------");

  policer_ndpi_named_t *r;
  vec_foreach (r, pm->named_policers)
    {
      char exceed_str[32];
      if (r->exceed_action == POLICER_NDPI_ACTION_DSCP_MARK)
	snprintf (exceed_str, sizeof (exceed_str), "dscp-mark %u",
		  (unsigned) r->dscp);
      else
	snprintf (exceed_str, sizeof (exceed_str), "drop");

      vlib_cli_output (vm, "%-24s %-8u %-12u %-10u %-12s",
		       (char *) r->app_name, (unsigned) r->app_id,
		       (unsigned) r->rate_kbps, (unsigned) r->burst_bytes,
		       exceed_str);
    }

  vlib_cli_output (vm,
		   "\nSee 'show error | grep ndpi-policer' for packet counters.");
  return 0;
}

VLIB_CLI_COMMAND (show_policer_ndpi_cmd, static) = {
  .path = "show policer-ndpi",
  .short_help = "show policer-ndpi",
  .function = show_policer_ndpi_fn,
};

/* ---------- set interface policer-ndpi ---------- */

static clib_error_t *
set_interface_policer_ndpi_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");

  int rv = policer_ndpi_interface_enable_disable (sw_if_index, enable);
  if (rv)
    return clib_error_return (0,
			      "policer_ndpi_interface_enable_disable failed: %d",
			      rv);

  vlib_cli_output (vm, "policer-ndpi %s on %U",
		   enable ? "enabled" : "disabled",
		   format_vnet_sw_if_index_name, vnm, sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (set_interface_policer_ndpi_cmd, static) = {
  .path = "set interface policer-ndpi",
  .short_help = "set interface policer-ndpi <interface> (enable|disable)",
  .function = set_interface_policer_ndpi_fn,
};
