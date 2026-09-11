/*
 * policy_cli.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policy_cli.c - vppctl commands for vpp-policy.
 *
 * Commands:
 *   set policy app <name> action (drop|permit)
 *   set policy default-action (drop|permit)
 *   clear policy app <name>
 *   show policy
 *   set interface policy <interface> (enable|disable)
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <policy/policy.h>

/* ---------- set policy app ---------- */

static clib_error_t *
set_policy_app_fn (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;
  u8 action = POLICY_ACTION_PERMIT;
  int action_set = 0;

  /* The CLI path is "set policy app"; remaining input is "<name> action ...". */
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "app name required");

  if (!unformat (input, "%s", &app_name))
    return clib_error_return (0, "app name required");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "action drop"))
	{
	  action = POLICY_ACTION_DROP;
	  action_set = 1;
	}
      else if (unformat (input, "action permit"))
	{
	  action = POLICY_ACTION_PERMIT;
	  action_set = 1;
	}
      else
	{
	  vec_free (app_name);
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  if (!app_name)
    return clib_error_return (0, "app name required");
  if (!action_set)
    {
      vec_free (app_name);
      return clib_error_return (0, "action (drop|permit) required");
    }

  int rv = policy_set_app (app_name, action);
  if (rv)
    {
      clib_error_t *e =
	clib_error_return (0, "unknown application '%s' — check nDPI app name",
			   app_name);
      vec_free (app_name);
      return e;
    }

  vlib_cli_output (vm, "policy: %s → %s", app_name,
		   action == POLICY_ACTION_DROP ? "drop" : "permit");
  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (set_policy_app_cmd, static) = {
  .path = "set policy app",
  .short_help = "set policy app <name> action (drop|permit)",
  .function = set_policy_app_fn,
};

/* ---------- set policy default-action ---------- */

static clib_error_t *
set_policy_default_action_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  u8 action = POLICY_ACTION_PERMIT;
  int action_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "drop"))
	{
	  action = POLICY_ACTION_DROP;
	  action_set = 1;
	}
      else if (unformat (input, "permit"))
	{
	  action = POLICY_ACTION_PERMIT;
	  action_set = 1;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (!action_set)
    return clib_error_return (0, "(drop|permit) required");

  policy_set_default_action (action);
  vlib_cli_output (vm, "policy: default action set to %s",
		   action == POLICY_ACTION_DROP ? "drop" : "permit");
  return 0;
}

VLIB_CLI_COMMAND (set_policy_default_cmd, static) = {
  .path = "set policy default-action",
  .short_help = "set policy default-action (drop|permit)",
  .function = set_policy_default_action_fn,
};

/* ---------- clear policy app ---------- */

static clib_error_t *
clear_policy_app_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  u8 *app_name = 0;

  /* CLI path is "clear policy app"; remaining input is just the name. */
  if (!unformat (input, "%s", &app_name))
    return clib_error_return (0, "app name required");

  policy_clear_app (app_name);
  vlib_cli_output (vm, "policy: rule for '%s' removed", app_name);
  vec_free (app_name);
  return 0;
}

VLIB_CLI_COMMAND (clear_policy_app_cmd, static) = {
  .path = "clear policy app",
  .short_help = "clear policy app <name>",
  .function = clear_policy_app_fn,
};

/* ---------- show policy ---------- */

static clib_error_t *
show_policy_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  policy_main_t *pm = &policy_main;

  vlib_cli_output (vm, "Default action: %s\n",
		   pm->default_action == POLICY_ACTION_DROP ? "drop" : "permit");

  if (vec_len (pm->named_rules) == 0)
    {
      vlib_cli_output (vm, "  No per-app rules configured.");
      return 0;
    }

  vlib_cli_output (vm, "%-32s %-8s %-8s", "Application", "ID", "Action");
  vlib_cli_output (vm, "%-32s %-8s %-8s",
		   "--------------------------------", "--------", "--------");

  policy_named_rule_t *r;
  vec_foreach (r, pm->named_rules)
    {
      vlib_cli_output (vm, "%-32s %-8u %-8s", (char *) r->app_name,
		       (unsigned) r->app_id,
		       r->action == POLICY_ACTION_DROP ? "drop" : "permit");
    }

  vlib_cli_output (vm,
		   "\nSee 'show error | grep ndpi-policy' for packet counters.");
  return 0;
}

VLIB_CLI_COMMAND (show_policy_cmd, static) = {
  .path = "show policy",
  .short_help = "show policy",
  .function = show_policy_fn,
};

/* ---------- set interface policy ---------- */

static clib_error_t *
set_interface_policy_fn (vlib_main_t *vm, unformat_input_t *input,
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

  int rv = policy_interface_enable_disable (sw_if_index, enable);
  if (rv)
    return clib_error_return (0,
			      "policy_interface_enable_disable failed: %d", rv);

  vlib_cli_output (vm, "policy %s on %U", enable ? "enabled" : "disabled",
		   format_vnet_sw_if_index_name, vnm, sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (set_interface_policy_cmd, static) = {
  .path = "set interface policy",
  .short_help = "set interface policy <interface> (enable|disable)",
  .function = set_interface_policy_fn,
};
