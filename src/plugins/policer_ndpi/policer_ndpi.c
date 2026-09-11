/*
 * policer_ndpi.c - vpp-policer-ndpi plugin init and public API.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <policer_ndpi/policer_ndpi.h>
#include <vnet/policer/xlate.h>
#include <string.h>
#include <stdio.h>

policer_ndpi_main_t policer_ndpi_main;

/* Resolve an nDPI application name string to its numeric protocol ID. */
static u16
policer_ndpi_resolve_app_id (const u8 *name)
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
policer_ndpi_set_app (const u8 *app_name, u32 rate_kbps, u32 burst_bytes,
		       u8 exceed_action, ip_dscp_t dscp)
{
  policer_ndpi_main_t *pm = &policer_ndpi_main;
  vnet_policer_main_t *vpm = &vnet_policer_main;

  u16 app_id = policer_ndpi_resolve_app_id (app_name);
  if (app_id == (u16) ~0u)
    return -1; /* unknown application */

  /* Build a unique policer name: "ndpi-<app_name>". */
  char pol_name[80];
  snprintf (pol_name, sizeof (pol_name), "ndpi-%s", (const char *) app_name);

  /* Configure a 1R2C (single-rate, two-colour) policer. */
  qos_pol_cfg_params_st cfg;
  clib_memset (&cfg, 0, sizeof (cfg));
  cfg.rb.kbps.cir_kbps = rate_kbps;
  cfg.rb.kbps.cb_bytes = burst_bytes;
  cfg.rb.kbps.eb_bytes = 0; /* 0 for 1R2C (only cb used) */
  cfg.rate_type = QOS_RATE_KBPS;
  cfg.rnd_type = QOS_ROUND_TO_CLOSEST;
  cfg.rfc = QOS_POLICER_TYPE_1R2C;

  /* Conform: transmit. Exceed/violate: depends on exceed_action. */
  cfg.conform_action.action_type = QOS_ACTION_TRANSMIT;
  if (exceed_action == POLICER_NDPI_ACTION_DSCP_MARK)
    {
      cfg.exceed_action.action_type = QOS_ACTION_MARK_AND_TRANSMIT;
      cfg.exceed_action.dscp = dscp;
      cfg.violate_action.action_type = QOS_ACTION_MARK_AND_TRANSMIT;
      cfg.violate_action.dscp = dscp;
    }
  else
    {
      cfg.exceed_action.action_type = QOS_ACTION_DROP;
      cfg.violate_action.action_type = QOS_ACTION_DROP;
    }

  u32 pol_index = ~0;

  /* Check if a policer by this name already exists. */
  uword *p =
    hash_get_mem (vpm->policer_index_by_name, (u8 *) pol_name);
  if (p)
    {
      pol_index = (u32) p[0];
      if (policer_update (pm->vlib_main, pol_index, &cfg))
	return -2;
    }
  else
    {
      if (policer_add (pm->vlib_main, (u8 *) pol_name, &cfg, &pol_index))
	return -3;
    }

  /* Update the data-plane vec under worker barrier. */
  vlib_worker_thread_barrier_sync (pm->vlib_main);
  vec_validate (pm->app_policers, app_id);
  pm->app_policers[app_id].policer_index = pol_index;
  pm->app_policers[app_id].exceed_action = exceed_action;
  pm->app_policers[app_id].dscp = dscp;
  pm->app_policers[app_id].valid = 1;
  vlib_worker_thread_barrier_release (pm->vlib_main);

  /* Update or insert named entry. */
  policer_ndpi_named_t *r;
  vec_foreach (r, pm->named_policers)
    {
      if (r->app_id == app_id)
	{
	  r->rate_kbps = rate_kbps;
	  r->burst_bytes = burst_bytes;
	  r->exceed_action = exceed_action;
	  r->dscp = dscp;
	  return 0;
	}
    }

  policer_ndpi_named_t nr;
  clib_memset (&nr, 0, sizeof (nr));
  strncpy ((char *) nr.app_name, (const char *) app_name,
	   sizeof (nr.app_name) - 1);
  nr.app_id = app_id;
  nr.rate_kbps = rate_kbps;
  nr.burst_bytes = burst_bytes;
  nr.exceed_action = exceed_action;
  nr.dscp = dscp;
  vec_add1 (pm->named_policers, nr);
  return 0;
}

int
policer_ndpi_clear_app (const u8 *app_name)
{
  policer_ndpi_main_t *pm = &policer_ndpi_main;

  u16 app_id = policer_ndpi_resolve_app_id (app_name);
  if (app_id == (u16) ~0u)
    return -1;

  /* Save and clear the data-plane entry. */
  u32 saved_pol_index = ~0;
  vlib_worker_thread_barrier_sync (pm->vlib_main);
  if (app_id < vec_len (pm->app_policers))
    {
      saved_pol_index = pm->app_policers[app_id].policer_index;
      pm->app_policers[app_id].valid = 0;
      pm->app_policers[app_id].policer_index = ~0;
    }
  vlib_worker_thread_barrier_release (pm->vlib_main);

  /* Delete the VPP policer engine entry. */
  if (saved_pol_index != ~0u)
    policer_del (pm->vlib_main, saved_pol_index);

  /* Remove from named list. */
  u32 i;
  vec_foreach_index (i, pm->named_policers)
    {
      if (pm->named_policers[i].app_id == app_id)
	{
	  vec_del1 (pm->named_policers, i);
	  return 0;
	}
    }
  return 0;
}

int
policer_ndpi_interface_enable_disable (u32 sw_if_index, int enable)
{
  return vnet_feature_enable_disable ("ip4-unicast", "ndpi-policer",
				      sw_if_index, enable, 0, 0);
}

static clib_error_t *
policer_ndpi_init (vlib_main_t *vm)
{
  policer_ndpi_main_t *pm = &policer_ndpi_main;
  pm->vlib_main = vm;
  pm->log_class = vlib_log_register_class ("policer-ndpi", 0);

  vlib_log_info (pm->log_class, "vpp-policer-ndpi %s initialized",
		 POLICER_NDPI_VERSION);
  return 0;
}

VLIB_INIT_FUNCTION (policer_ndpi_init);
