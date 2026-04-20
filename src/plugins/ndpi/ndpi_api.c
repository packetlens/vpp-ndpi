/*
 * ndpi_api.c - Binary API handlers for vpp-ndpi.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <ndpi/ndpi.h>

#include <ndpi.api_enum.h>
#include <ndpi.api_types.h>

#define REPLY_MSG_ID_BASE (ndpi_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ndpi_interface_enable_disable_t_handler (
  vl_api_ndpi_interface_enable_disable_t *mp)
{
  vl_api_ndpi_interface_enable_disable_reply_t *rmp;
  int rv;

  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  rv = ndpi_interface_enable_disable (sw_if_index, (int) mp->enable_disable);

  REPLY_MACRO (VL_API_NDPI_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ndpi_stats_get_t_handler (vl_api_ndpi_stats_get_t *mp)
{
  vl_api_ndpi_stats_get_reply_t *rmp;
  vl_api_registration_t *reg;
  ndpi_main_t *nm = &ndpi_main;
  int rv = 0;

  u64 pkts_cached = 0, pkts_scanned = 0;
  u64 flows_created = 0, flows_classified = 0, flows_gave_up = 0;
  u64 calls = 0;

  for (u32 w = 0; w < vec_len (nm->per_worker); w++)
    {
      ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, w);
      pkts_cached += pw->packets_cached;
      pkts_scanned += pw->packets_scanned;
      flows_created += pw->flows_created;
      flows_classified += pw->flows_classified;
      flows_gave_up += pw->flows_gave_up;
      calls += pw->ndpi_calls;
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_NDPI_STATS_GET_REPLY + REPLY_MSG_ID_BASE);
  rmp->context = mp->context;
  rmp->retval = clib_host_to_net_i32 (rv);
  rmp->packets_cached = clib_host_to_net_u64 (pkts_cached);
  rmp->packets_scanned = clib_host_to_net_u64 (pkts_scanned);
  rmp->flows_created = clib_host_to_net_u64 (flows_created);
  rmp->flows_classified = clib_host_to_net_u64 (flows_classified);
  rmp->flows_gave_up = clib_host_to_net_u64 (flows_gave_up);
  rmp->ndpi_calls = clib_host_to_net_u64 (calls);

  vl_api_send_msg (reg, (u8 *) rmp);
}

#include <ndpi.api.c>

static clib_error_t *
ndpi_api_hookup (vlib_main_t *vm)
{
  ndpi_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ndpi_api_hookup);
