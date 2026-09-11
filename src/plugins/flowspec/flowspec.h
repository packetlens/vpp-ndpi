/*
 * flowspec.h
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec.h - vpp-flowspec: BGP FlowSpec push on application threshold.
 *
 * Monitors per-app traffic stats from vpp-ndpi. When configurable byte-rate
 * thresholds are crossed, writes JSON notification events to a Unix domain
 * socket. A companion process (flowspec-ctrl) reads events and announces
 * BGP FlowSpec rules to upstream PE routers via GoBGP.
 *
 * Compiled into ndpi_plugin.so alongside the ndpi and ipfix code.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_vpp_flowspec_h__
#define __included_vpp_flowspec_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <ndpi/ndpi.h>

#define FLOWSPEC_PLUGIN_VERSION "0.1.0"

/* Actions that can be taken on matching traffic at the PE router. */
#define FLOWSPEC_ACTION_DROP        0
#define FLOWSPEC_ACTION_RATE_LIMIT  1

/* Max distinct dst /32 prefixes collected from the flow table per app
 * per evaluation cycle. Prevents unbounded memory use under large flow tables. */
#define FLOWSPEC_MAX_DST_PER_APP    16

/* Default path of the Unix domain socket written to by this plugin.
 * flowspec-ctrl must listen on the same path. */
#define FLOWSPEC_DEFAULT_SOCK_PATH  "/tmp/flowspec-notify.sock"

/* Default hold time in seconds (rule stays active after traffic drops). */
#define FLOWSPEC_DEFAULT_HOLD_SEC   60

/* Hysteresis ratio: withdraw rule when traffic falls below
 * (bps_threshold * FLOWSPEC_WITHDRAW_HYSTERESIS). */
#define FLOWSPEC_WITHDRAW_HYSTERESIS 0.1

/* ---------------------------------------------------------------------------
 * Per-threshold state.  One entry per configured app threshold.
 * ---------------------------------------------------------------------------*/
typedef struct
{
  /* nDPI application protocol ID (index into per_worker app_counters_by_intf).
   * Set to ~0u before the name has been resolved to a numeric ID. */
  u16 app_id;

  /* Human-readable app name as configured by CLI.  NUL-terminated. */
  u8 app_name[64];

  /* Action and parameters. */
  u8 action;        /* FLOWSPEC_ACTION_DROP | FLOWSPEC_ACTION_RATE_LIMIT */
  u64 bps_threshold; /* bytes per second to trigger rule */
  u64 rate_bps;      /* rate-limit in bytes/sec (RATE_LIMIT only) */
  u32 hold_sec;      /* seconds to hold rule after traffic drops below threshold */

  /* State machine. */
  u8 triggered; /* 0 = normal, 1 = triggered (rule announced) */
  f64 triggered_at; /* VPP time when last triggered */
} flowspec_threshold_t;

/* ---------------------------------------------------------------------------
 * Plugin main struct.
 * ---------------------------------------------------------------------------*/
typedef struct
{
  /* Configured thresholds — vec, one per CLI-added app. */
  flowspec_threshold_t *thresholds;

  /* Unix domain socket to flowspec-ctrl.
   * sock_fd == -1 means not currently connected. */
  int sock_fd;
  u8 *sock_path; /* heap-allocated path string */

  /* Previous-cycle per-app byte totals for delta (bytes/sec) calculation. */
  u64 prev_app_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS];
  f64 prev_poll_time;

  /* Counters */
  u64 events_sent;
  u64 socket_errors;
  u64 threshold_crossings;

  u32 log_class;
  vlib_main_t *vlib_main;
} flowspec_main_t;

extern flowspec_main_t flowspec_main;

/* flowspec.c — public API called from flowspec_cli.c */
int flowspec_set_socket_path (const char *path);
int flowspec_threshold_set (const u8 *app_name, u64 bps_threshold, u8 action,
			    u64 rate_bps, u32 hold_sec);
int flowspec_threshold_clear (const u8 *app_name);

#endif /* __included_vpp_flowspec_h__ */
