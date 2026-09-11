/*
 * ipfix_api.c - Binary API handlers for vpp-ipfix.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <ipfix/ipfix.h>

#include <ipfix.api_enum.h>
#include <ipfix.api_types.h>

#define REPLY_MSG_ID_BASE (ipfix_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ndpi_ipfix_exporter_set_t_handler (
  vl_api_ndpi_ipfix_exporter_set_t *mp)
{
  vl_api_ndpi_ipfix_exporter_set_reply_t *rmp;
  int rv;

  ip4_address_t collector_ip, src_ip;
  clib_memcpy (&collector_ip, mp->collector_ip, sizeof (collector_ip));
  clib_memcpy (&src_ip, mp->src_ip, sizeof (src_ip));
  u16 port = clib_net_to_host_u16 (mp->collector_port);

  rv = ipfix_exporter_add (&collector_ip, port, &src_ip);
  REPLY_MACRO (VL_API_NDPI_IPFIX_EXPORTER_SET_REPLY);
}

static void
vl_api_ndpi_ipfix_exporter_clear_t_handler (
  vl_api_ndpi_ipfix_exporter_clear_t *mp)
{
  vl_api_ndpi_ipfix_exporter_clear_reply_t *rmp;
  int rv = 0;

  ipfix_exporter_del_all ();
  REPLY_MACRO (VL_API_NDPI_IPFIX_EXPORTER_CLEAR_REPLY);
}

static void
vl_api_ndpi_ipfix_enable_disable_t_handler (
  vl_api_ndpi_ipfix_enable_disable_t *mp)
{
  vl_api_ndpi_ipfix_enable_disable_reply_t *rmp;
  int rv;

  rv = ipfix_enable_disable ((int) mp->enable);
  REPLY_MACRO (VL_API_NDPI_IPFIX_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ndpi_ipfix_stats_get_t_handler (vl_api_ndpi_ipfix_stats_get_t *mp)
{
  vl_api_ndpi_ipfix_stats_get_reply_t *rmp;
  vl_api_registration_t *reg;
  ipfix_main_t *im = &ipfix_main;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_NDPI_IPFIX_STATS_GET_REPLY +
			   REPLY_MSG_ID_BASE);
  rmp->context = mp->context;
  rmp->retval = clib_host_to_net_i32 (rv);
  rmp->flows_exported = clib_host_to_net_u64 (im->flows_exported);
  rmp->pdus_sent = clib_host_to_net_u64 (im->pdus_sent);
  rmp->ring_overflow_drops = clib_host_to_net_u64 (im->ring_overflow_drops);
  rmp->udp_send_errors = clib_host_to_net_u64 (im->udp_send_errors);
  rmp->templates_sent = clib_host_to_net_u64 (im->templates_sent);

  vl_api_send_msg (reg, (u8 *) rmp);
}

#include <ipfix.api.c>

static clib_error_t *
ipfix_api_hookup (vlib_main_t *vm)
{
  ipfix_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ipfix_api_hookup);
