/*
 * policy.c - vpp-policy plugin init and public API.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <policy/policy.h>
#include <string.h>

policy_main_t policy_main;

/* Resolve an nDPI application name string to its numeric protocol ID.
 * Uses worker 0's detection module (all workers share the same protocol table).
 * Returns ~0u if not found or if nDPI is not yet initialised. */
static u16
policy_resolve_app_id (const u8 *name)
{
  ndpi_main_t *nm = &ndpi_main;

  if (vec_len (nm->per_worker) == 0)
    return (u16) ~0u;

  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, 0);
  if (!pw->ndpi)
    return (u16) ~0u;

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

int
policy_set_app (const u8 *app_name, u8 action)
{
  policy_main_t *pm = &policy_main;

  u16 app_id = policy_resolve_app_id (app_name);
  if (app_id == (u16) ~0u)
    return -1; /* unknown application */

  /* Update the data-plane vec under worker barrier. */
  vlib_worker_thread_barrier_sync (pm->vlib_main);
  vec_validate (pm->app_rules, app_id);
  pm->app_rules[app_id].action = action;
  pm->app_rules[app_id].valid = 1;
  vlib_worker_thread_barrier_release (pm->vlib_main);

  /* Update or insert the named-rule entry for 'show policy'. */
  policy_named_rule_t *r;
  vec_foreach (r, pm->named_rules)
    {
      if (r->app_id == app_id)
	{
	  r->action = action;
	  return 0;
	}
    }

  policy_named_rule_t nr;
  clib_memset (&nr, 0, sizeof (nr));
  strncpy ((char *) nr.app_name, (const char *) app_name,
	   sizeof (nr.app_name) - 1);
  nr.app_id = app_id;
  nr.action = action;
  vec_add1 (pm->named_rules, nr);
  return 0;
}

int
policy_clear_app (const u8 *app_name)
{
  policy_main_t *pm = &policy_main;

  u16 app_id = policy_resolve_app_id (app_name);
  if (app_id == (u16) ~0u)
    return -1;

  /* Clear in the data-plane vec. */
  vlib_worker_thread_barrier_sync (pm->vlib_main);
  if (app_id < vec_len (pm->app_rules))
    {
      pm->app_rules[app_id].valid = 0;
      pm->app_rules[app_id].action = 0;
    }
  vlib_worker_thread_barrier_release (pm->vlib_main);

  /* Remove from named_rules. */
  u32 i;
  vec_foreach_index (i, pm->named_rules)
    {
      if (pm->named_rules[i].app_id == app_id)
	{
	  vec_del1 (pm->named_rules, i);
	  return 0;
	}
    }
  return 0; /* rule cleared even if not in named list */
}

int
policy_set_default_action (u8 action)
{
  policy_main.default_action = action;
  return 0;
}

int
policy_interface_enable_disable (u32 sw_if_index, int enable)
{
  return vnet_feature_enable_disable ("ip4-unicast", "ndpi-policy",
				      sw_if_index, enable, 0, 0);
}

static clib_error_t *
policy_init (vlib_main_t *vm)
{
  policy_main_t *pm = &policy_main;
  pm->vlib_main = vm;
  pm->log_class = vlib_log_register_class ("policy", 0);
  pm->default_action = POLICY_ACTION_PERMIT;

  vlib_log_info (pm->log_class, "vpp-policy %s initialized",
		 POLICY_PLUGIN_VERSION);
  return 0;
}

VLIB_INIT_FUNCTION (policy_init);
