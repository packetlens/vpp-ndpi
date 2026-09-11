/*
 * ipfix.h - vpp-ipfix plugin: nDPI-enriched IPFIX export (RFC 7011)
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_vpp_ipfix_h__
#define __included_vpp_ipfix_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/vec.h>
#include <ndpi/ndpi.h>

#define IPFIX_PLUGIN_VERSION    "0.1.0"

/* ntop Private Enterprise Number (used for nDPI Information Elements) */
#define IPFIX_NTOP_PEN          35632

/* Template IDs assigned by this exporter */
#define IPFIX_TEMPLATE_ID_V4    256
#define IPFIX_TEMPLATE_ID_V6    257

/* IPFIX well-known set IDs */
#define IPFIX_SET_ID_TEMPLATE   2
#define IPFIX_VERSION           10

/* Maximum collectors configured simultaneously */
#define IPFIX_MAX_COLLECTORS    4

/* PDU payload limit (MTU headroom for IPv4/UDP) */
#define IPFIX_MAX_PDU_BYTES     1400

/* Template resend interval (seconds) */
#define IPFIX_TEMPLATE_REFRESH  600

/* ---------------------------------------------------------------------------
 * Pending record: copied from ndpi_flow_t at expiry time.
 * Stored on the main thread; no locking needed.
 * ---------------------------------------------------------------------------*/

#define IPFIX_APP_NAME_LEN  32
#define IPFIX_SNI_LEN       64
#define IPFIX_JA3_LEN       33

typedef struct
{
  /* 5-tuple */
  ip4_address_t src4;
  ip4_address_t dst4;
  u16 src_port;
  u16 dst_port;
  u8 protocol;

  /* Flow counters */
  u64 byte_count;
  u64 packet_count;
  u64 first_seen_ms; /* milliseconds since epoch */
  u64 last_seen_ms;

  /* Interface */
  u32 interface_index;

  /* nDPI metadata */
  u16 app_protocol;
  u8 category;
  u8 pad;
  u32 risk;
  u8 app_name[IPFIX_APP_NAME_LEN];
  u8 sni[IPFIX_SNI_LEN];
  u8 ja3_hash[IPFIX_JA3_LEN];
  u8 pad2;
} ipfix_record_v4_t;

/* ---------------------------------------------------------------------------
 * Collector config
 * ---------------------------------------------------------------------------*/
typedef struct
{
  ip4_address_t ip;
  u16 port;
  int fd; /* UDP socket fd, -1 = not open */
} ipfix_collector_t;

/* ---------------------------------------------------------------------------
 * Plugin main struct
 * ---------------------------------------------------------------------------*/
typedef struct
{
  vlib_main_t *vlib_main;

  /* Enabled flag */
  u8 enabled;

  /* Collectors */
  ipfix_collector_t collectors[IPFIX_MAX_COLLECTORS];
  u32 n_collectors;

  /* Source IP for UDP socket bind (optional; 0 = INADDR_ANY) */
  ip4_address_t src_ip;

  /* Pending records — filled by the expiry callback, drained by the
   * ipfix-export-process node. Both happen on the VPP main thread. */
  ipfix_record_v4_t *pending; /* vec */

  /* IPFIX sequence number (counts data records sent, not PDUs) */
  u32 seq_no;

  /* Time of last template send (seconds) */
  f64 last_template_sent;

  /* Offset to convert VPP monotonic time to Unix epoch (seconds).
   * Computed once at init: unix_epoch_offset = time(NULL) - vlib_time_now(vm) */
  f64 unix_epoch_offset;

  /* Counters */
  u64 flows_exported;
  u64 pdus_sent;
  u64 ring_overflow_drops; /* pending vec hard cap */
  u64 udp_send_errors;
  u64 templates_sent;

  u16 msg_id_base;
  vlib_log_class_t log_class;
} ipfix_main_t;

extern ipfix_main_t ipfix_main;

/* ipfix.c */
int ipfix_exporter_add (ip4_address_t *collector_ip, u16 port,
			ip4_address_t *src_ip);
void ipfix_exporter_del_all (void);
int ipfix_enable_disable (int enable);

/* ipfix_export.c */
void ipfix_send_templates (ipfix_main_t *im, f64 now);
void ipfix_flush_pending (ipfix_main_t *im);

#endif /* __included_vpp_ipfix_h__ */
