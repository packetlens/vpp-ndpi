/*
 * flowspec_recv.h
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec_recv.h - vpp-flowspec-recv: BGP FlowSpec receive and enforce.
 *
 * Receives FlowSpec rules from a companion Go sidecar (flowspec-recv) that
 * watches incoming BGP FlowSpec NLRIs from an upstream peer.  Rules are
 * written as newline-delimited JSON over a Unix domain socket.  The VPP
 * data-plane graph node enforces them inline on ip4-unicast — drop or
 * token-bucket rate-limit matching packets by destination prefix.
 *
 * This plugin is standalone: it does NOT depend on vpp-ndpi.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_flowspec_recv_h__
#define __included_flowspec_recv_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vlib/vlib.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police.h>

#define FLOWSPEC_RECV_VERSION     "0.1.0"
#define FLOWSPEC_RECV_SOCK_PATH   "/tmp/flowspec-recv.sock"

#define FLOWSPEC_RECV_ACTION_DROP       0
#define FLOWSPEC_RECV_ACTION_RATE_LIMIT 1

/* One installed FlowSpec rule.  Matched by LPM on dst IP. */
typedef struct
{
  ip4_address_t dst;   /* network address (host-byte-order masked) */
  u8  prefix_len;      /* 0–32 */
  u8  action;          /* FLOWSPEC_RECV_ACTION_* */
  u64 rate_bps;        /* bytes/sec — rate-limit only */
  u32 pol_index;       /* VPP policer pool index; ~0 = none */
  u8  rule_id[37];     /* NUL-terminated UUID string from sidecar */
  u8  valid;           /* 1 = active */
} flowspec_recv_rule_t;

/* Plugin main struct. */
typedef struct
{
  /* Rule table — vec, barrier-protected writes, lock-free reads on hot path. */
  flowspec_recv_rule_t *rules;

  /* Unix socket (connect to Go sidecar). */
  int  sock_fd;        /* -1 = not connected */
  u8  *sock_path;      /* heap-allocated, NUL-terminated */

  /* Line accumulation buffer for streaming recv(). */
  u8  *recv_buf;
  u32  recv_buf_len;

  /* Counters. */
  u64 rules_installed;
  u64 rules_removed;
  u64 socket_errors;
  u64 pkts_dropped;
  u64 pkts_rate_limited;

  u32 log_class;
  vlib_main_t *vlib_main;
} flowspec_recv_main_t;

extern flowspec_recv_main_t flowspec_recv_main;

/* API called from flowspec_recv_cli.c */
int flowspec_recv_set_socket_path (const char *path);
int flowspec_recv_enable_disable_interface (u32 sw_if_index, int enable);

#endif /* __included_flowspec_recv_h__ */
