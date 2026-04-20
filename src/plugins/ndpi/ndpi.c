/*
 * ndpi.c - VPP nDPI plugin init and interface enable/disable.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <ndpi/ndpi.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

ndpi_main_t ndpi_main;

static clib_error_t *
ndpi_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  ndpi_main_t *nm = &ndpi_main;

  nm->flows_per_worker = 1 << 16; /* 64K per worker default */
  nm->tcp_idle_timeout = NDPI_FLOW_TIMEOUT_TCP_DFLT;
  nm->udp_idle_timeout = NDPI_FLOW_TIMEOUT_UDP_DFLT;
  nm->classify_max_pkts = NDPI_CLASSIFY_MAX_PKTS;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "flows-per-worker %u", &nm->flows_per_worker))
	;
      else if (unformat (input, "tcp-idle-timeout %f", &nm->tcp_idle_timeout))
	;
      else if (unformat (input, "udp-idle-timeout %f", &nm->udp_idle_timeout))
	;
      else if (unformat (input, "classify-max-packets %u",
			 &nm->classify_max_pkts))
	;
      else
	return clib_error_return (0, "unknown ndpi config: '%U'",
				  format_unformat_error, input);
    }
  return 0;
}
VLIB_CONFIG_FUNCTION (ndpi_config_fn, "ndpi");

static clib_error_t *
ndpi_init (vlib_main_t *vm)
{
  ndpi_main_t *nm = &ndpi_main;
  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main ();
  nm->log_class = vlib_log_register_class ("ndpi", 0);

  /* Apply defaults if config fn never ran */
  if (nm->flows_per_worker == 0)
    nm->flows_per_worker = 1 << 16;
  if (nm->tcp_idle_timeout == 0.0)
    nm->tcp_idle_timeout = NDPI_FLOW_TIMEOUT_TCP_DFLT;
  if (nm->udp_idle_timeout == 0.0)
    nm->udp_idle_timeout = NDPI_FLOW_TIMEOUT_UDP_DFLT;
  if (nm->classify_max_pkts == 0)
    nm->classify_max_pkts = NDPI_CLASSIFY_MAX_PKTS;

  u32 n_workers = vlib_num_workers ();
  u32 n_threads = (n_workers == 0) ? 1 : n_workers;
  vec_validate (nm->per_worker, n_threads - 1);

  for (u32 i = 0; i < n_threads; i++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, i);
      if (ndpi_flow_table_init (pw, nm->flows_per_worker) != 0)
	return clib_error_return (0, "flow table init failed worker %u", i);
      if (ndpi_worker_engine_init (pw) != 0)
	return clib_error_return (0, "nDPI engine init failed worker %u", i);
      pw->initialized = 1;
    }

  ndpi_stats_init (nm);

  vlib_log_info (nm->log_class,
		 "initialized (%u threads, %u flows/worker, nDPI v%s)",
		 n_threads, nm->flows_per_worker,
		 ndpi_revision ());
  return 0;
}
VLIB_INIT_FUNCTION (ndpi_init);

VLIB_PLUGIN_REGISTER () = {
  .version = NDPI_PLUGIN_VERSION,
  .description = "nDPI observability",
};

int
ndpi_interface_enable_disable (u32 sw_if_index, int enable)
{
  ndpi_main_t *nm = &ndpi_main;
  int rv;

  rv = vnet_feature_enable_disable ("ip4-unicast", "ndpi-observe",
				    sw_if_index, enable, 0, 0);
  if (rv)
    return rv;

  rv = vnet_feature_enable_disable ("ip6-unicast", "ndpi-observe",
				    sw_if_index, enable, 0, 0);
  if (rv)
    return rv;

  nm->enabled_interfaces =
    clib_bitmap_set (nm->enabled_interfaces, sw_if_index, enable ? 1 : 0);

  vlib_log_info (nm->log_class, "sw_if_index %u %s", sw_if_index,
		 enable ? "enabled" : "disabled");
  return 0;
}
