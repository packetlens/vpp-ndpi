/*
 * cdr.h
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * cdr.h - vpp-cdr: SIP call detail records via HEP3 to Homer.
 *
 * Mirrors every SIP packet (identified via nDPI app_id or port heuristic)
 * to a Homer heplify-server instance using HEP v3 (RFC-style UDP framing).
 * Homer then assembles per-call CDR records, SIP ladder diagrams, and
 * RTP quality metrics.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __CDR_H__
#define __CDR_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define CDR_VERSION             "1.0.0"
#define CDR_HEP_DEFAULT_PORT    9060
#define CDR_HEP_DEFAULT_AGENT   1

/* nDPI SIP protocol ID in 4.x — used as fallback when runtime lookup fails */
#define CDR_NDPI_SIP_PROTO_ID   87

/* Maximum bytes of SIP payload we copy into a HEP3 frame (avoids large allocs) */
#define CDR_HEP3_MAX_PAYLOAD    4096
/* Maximum total HEP3 frame size */
#define CDR_HEP3_MAX_FRAME      (CDR_HEP3_MAX_PAYLOAD + 256)

/* SIP well-known ports */
#define CDR_SIP_PORT_1          5060
#define CDR_SIP_PORT_2          5061

/* ── Main plugin state ───────────────────────────────────────────────────── */

typedef struct
{
  vlib_main_t  *vlib_main;
  vnet_main_t  *vnet_main;
  vlib_log_class_t log_class;

  /* HEP destination (0/0 = not configured) */
  u32  homer_ip4;         /* network byte order */
  u16  homer_port;        /* host byte order, default 9060 */
  int  hep_sock;          /* UDP socket fd; -1 = not open */

  /* HEP options */
  u32  capture_agent_id;  /* HEP chunk 0x000c */
  u8  *hep_password;      /* vec of bytes; NULL = no auth chunk */

  /* Enabled interfaces bitmap */
  uword *enabled_sw_if_indices;

  /* nDPI SIP protocol ID, resolved lazily on first packet */
  u16 sip_proto_id;       /* 0 = not yet resolved */

  /* Stats — written from worker threads; coarse, no atomics needed */
  u64 pkts_mirrored;
  u64 pkts_failed;
  u64 pkts_not_configured;  /* Homer not set up yet */
} cdr_main_t;

extern cdr_main_t cdr_main;

/* ── API ─────────────────────────────────────────────────────────────────── */

/** Enable / disable CDR mirroring on an interface. */
int cdr_interface_enable_disable (u32 sw_if_index, int enable);

/**
 * Open (or re-open) the UDP socket to Homer.
 * Idempotent — returns 0 immediately if already open.
 */
int cdr_hep_sock_open (cdr_main_t *cm);

/**
 * Build a HEP v3 frame into @out (max @out_max bytes).
 * All IP/port parameters are in network byte order.
 * Returns total bytes written, or -1 if frame would overflow.
 */
int cdr_build_hep3 (u8 *out, int out_max,
                    u32 src_ip4_net, u32 dst_ip4_net,
                    u16 src_port_net, u16 dst_port_net,
                    u8  ip_proto,
                    u32 ts_sec, u32 ts_usec,
                    u32 agent_id,
                    const u8 *password, u16 password_len,
                    const u8 *payload, u16 payload_len);

#endif /* __CDR_H__ */
