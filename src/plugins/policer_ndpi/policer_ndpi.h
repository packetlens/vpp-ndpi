/*
 * policer_ndpi.h
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policer_ndpi.h - vpp-policer-ndpi: per-app token-bucket rate limiting.
 *
 * Runs as a VPP feature node after ndpi-observe (and ndpi-policy if present)
 * in the ip4-unicast arc.  For each classified flow it applies a named VPP
 * policer (1R2C token bucket), dropping or DSCP-marking excess traffic.
 *
 * Each per-app policer is created via policer_add() and stored by index.
 * The data-plane node calls vnet_police_packet() at TSC rate.
 *
 * Compiled into ndpi_plugin.so alongside ndpi, ipfix, flowspec, policy.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_vpp_policer_ndpi_h__
#define __included_vpp_policer_ndpi_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police.h>
#include <ndpi/ndpi.h>

#define POLICER_NDPI_VERSION "0.1.0"

/* Exceed action: what to do when a packet is policed (EXCEED/VIOLATE). */
#define POLICER_NDPI_ACTION_DROP       0
#define POLICER_NDPI_ACTION_DSCP_MARK  1

/* Per-app policer entry.  Stored in a vec indexed by nDPI app_protocol ID. */
typedef struct
{
  u32 policer_index; /* index into vnet_policer_main.policers pool */
  u8 exceed_action;  /* POLICER_NDPI_ACTION_* */
  ip_dscp_t dscp;    /* DSCP value to mark when action=DSCP_MARK */
  u8 valid;          /* 1 = entry configured */
} policer_ndpi_app_t;

/* Named entry — stored for 'show policer-ndpi' display. */
typedef struct
{
  u8 app_name[64];   /* NUL-terminated */
  u16 app_id;
  u32 rate_kbps;
  u32 burst_bytes;
  u8 exceed_action;
  ip_dscp_t dscp;
} policer_ndpi_named_t;

/* Plugin main struct. */
typedef struct
{
  /* Data-plane vec: index = nDPI app_protocol ID.  Read on hot path.
   * Writes serialised with vlib_worker_thread_barrier_sync(). */
  policer_ndpi_app_t *app_policers;

  /* Named entries for display. */
  policer_ndpi_named_t *named_policers;

  u32 log_class;
  vlib_main_t *vlib_main;
} policer_ndpi_main_t;

extern policer_ndpi_main_t policer_ndpi_main;

/* policer_ndpi.c — public API used by policer_ndpi_cli.c */
int policer_ndpi_set_app (const u8 *app_name, u32 rate_kbps, u32 burst_bytes,
			   u8 exceed_action, ip_dscp_t dscp);
int policer_ndpi_clear_app (const u8 *app_name);
int policer_ndpi_interface_enable_disable (u32 sw_if_index, int enable);

#endif /* __included_vpp_policer_ndpi_h__ */
