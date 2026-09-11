/*
 * ndpi.h - VPP nDPI Observability Plugin
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __included_vpp_ndpi_h__
#define __included_vpp_ndpi_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>

#include <ndpi_api.h>
#include <ndpi_typedefs.h>

#define NDPI_PLUGIN_VERSION "0.1.0"

#define NDPI_MAX_SNI_LEN 64
#define NDPI_MAX_JA3_LEN 33
#define NDPI_CLASSIFY_MAX_PKTS 8
#define NDPI_FLOW_TIMEOUT_TCP_DFLT 300.0
#define NDPI_FLOW_TIMEOUT_UDP_DFLT 30.0
#define NDPI_CLASSIFY_TIMEOUT 5.0

/* ---------------------------------------------------------------------------
 * Flow table keys. Both families stored inline in the hash bucket via the
 * 16-byte / 48-byte slots to avoid a secondary pool lookup on the hot path.
 * ---------------------------------------------------------------------------*/

typedef struct
{
  ip4_address_t src;
  ip4_address_t dst;
  u16 src_port;
  u16 dst_port;
  u8 proto;
  u8 pad[3];
} ndpi_flow_key4_t;
STATIC_ASSERT_SIZEOF (ndpi_flow_key4_t, 16);

typedef struct
{
  ip6_address_t src;
  ip6_address_t dst;
  u16 src_port;
  u16 dst_port;
  u8 proto;
  u8 pad[11];
} ndpi_flow_key6_t;
STATIC_ASSERT_SIZEOF (ndpi_flow_key6_t, 48);

/* ---------------------------------------------------------------------------
 * Per-flow state. Stored in a per-worker pool. Bihash value is the pool
 * index.
 * ---------------------------------------------------------------------------*/

typedef struct
{
  u16 master_protocol;
  u16 app_protocol;
  u16 category;
  u8 classified; /* 0 = classifying, 1 = verdict cached */
  u8 give_up_count;
  u8 is_ip6;
  u8 pad0[3];

  u64 risk;      /* nDPI risk bitmask — extracted at classification time */

  struct ndpi_flow_struct *ndpi_flow; /* freed after verdict */

  u8 sni[NDPI_MAX_SNI_LEN];
  u8 ja3_hash[NDPI_MAX_JA3_LEN];

  u64 packet_count;
  u64 byte_count;

  f64 first_seen;
  f64 last_seen;

  u32 interface_index;

  /* Key retained for aging-time delete */
  union
  {
    ndpi_flow_key4_t key4;
    ndpi_flow_key6_t key6;
  };
} ndpi_flow_t;

/* ---------------------------------------------------------------------------
 * Per-interface aggregate counters, per worker.
 * ---------------------------------------------------------------------------*/

typedef struct
{
  u64 *packets; /* vec, indexed by ndpi app_protocol id */
  u64 *bytes;
  u64 *flows;
} ndpi_app_counters_t;

typedef struct
{
  u64 *packets; /* vec, indexed by category */
  u64 *bytes;
  u64 *flows;
} ndpi_cat_counters_t;

/* ---------------------------------------------------------------------------
 * Stats segment indices.  Registered once at init; updated every second by
 * the ndpi-stats-process node.  ~0u means "not registered" (Unknown proto).
 * ---------------------------------------------------------------------------*/

typedef struct
{
  /* Global scalar gauges */
  u32 flows_created;
  u32 flows_classified;
  u32 flows_gave_up;
  u32 flows_active;
  u32 packets_scanned;
  u32 packets_cached;
  u32 ndpi_calls;

  /* Per-protocol gauges, indexed by nDPI app_protocol id.
   * Entry value is STAT_SEGMENT_INDEX_INVALID when not registered. */
  u32 *app_bytes;   /* vec[app_id] → stats segment entry index */
  u32 *app_packets;
  u32 *app_flows;
} ndpi_stats_seg_t;

/* ---------------------------------------------------------------------------
 * Per-worker state. Allocated once at plugin init.
 * ---------------------------------------------------------------------------*/

typedef struct
{
  struct ndpi_detection_module_struct *ndpi;

  ndpi_flow_t *flows; /* pool */

  clib_bihash_16_8_t flow_ht4;
  clib_bihash_48_8_t flow_ht6;

  /* Per-interface counter vectors, indexed by sw_if_index */
  ndpi_app_counters_t *app_counters_by_intf; /* vec */
  ndpi_cat_counters_t *cat_counters_by_intf; /* vec */

  u64 packets_cached;
  u64 packets_scanned;
  u64 flows_created;
  u64 flows_classified;
  u64 flows_gave_up;
  u64 ndpi_calls;

  u32 age_cursor;

  int initialized;
} ndpi_per_worker_t;

/* Flow-expiry callback. Registered by downstream plugins (e.g. vpp-ipfix).
 * Called from the aging sweep inside ndpi_stats_process, while the worker
 * barrier is held. The callback MUST NOT block or allocate large amounts of
 * memory. */
typedef void (*ndpi_flow_expire_cb_t) (ndpi_per_worker_t *pw,
				       const ndpi_flow_t *f, void *opaque);

/* Flow-classification callback (Phase 7).  Called once per flow from the
 * worker thread when nDPI reaches a final verdict.  Re-entrant; must not
 * block, allocate, or call any VPP API. */
typedef void (*ndpi_on_flow_classified_fn_t)(
    u32 src_ip4, u32 dst_ip4,
    u8 proto, u16 sport, u16 dport,
    u16 master_protocol, u16 app_protocol, u16 category,
    u64 risk,
    const u8 *sni, const u8 *ja3,
    u32 sw_if_index,
    void *ctx);

/* ---------------------------------------------------------------------------
 * Plugin main struct.
 * ---------------------------------------------------------------------------*/

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  ndpi_per_worker_t *per_worker; /* vec, one per worker */

  uword *enabled_interfaces; /* bitmap */

  /* Config */
  u32 flows_per_worker;
  f64 tcp_idle_timeout;
  f64 udp_idle_timeout;
  u8 classify_max_pkts;

  u16 msg_id_base;
  vlib_log_class_t log_class;

  /* Stats segment integration */
  ndpi_stats_seg_t stats_seg;

  /* Optional flow-expiry callback (registered by vpp-ipfix or similar) */
  ndpi_flow_expire_cb_t flow_expire_cb;
  void *flow_expire_cb_opaque;

  /* Optional flow-classification callback (Phase 7).
   * Called from the worker thread when nDPI reaches a final verdict. */
  ndpi_on_flow_classified_fn_t classify_cb;
  void    *classify_cb_ctx;
  u8       classify_cb_name[64];
  u64      classify_cb_calls;   /* approximate; no lock, summed in show */
} ndpi_main_t;


extern ndpi_main_t ndpi_main;

extern vlib_node_registration_t ndpi_observe_node;

typedef enum
{
  NDPI_NEXT_PASS,
  NDPI_N_NEXT,
} ndpi_next_t;

/* ndpi.c */
int ndpi_interface_enable_disable (u32 sw_if_index, int enable);

/* ndpi_ndpi.c */
int ndpi_worker_engine_init (ndpi_per_worker_t *pw);
void ndpi_worker_engine_cleanup (ndpi_per_worker_t *pw);
void ndpi_classify_packet (ndpi_per_worker_t *pw, ndpi_flow_t *f, u8 *ip_hdr,
			   u32 ip_len, f64 now);
const char *ndpi_app_name_for_id (ndpi_per_worker_t *pw, u16 app_id);
const char *ndpi_cat_name_for_id (ndpi_per_worker_t *pw, u16 cat_id);

/* ndpi_flow.c */
int ndpi_flow_table_init (ndpi_per_worker_t *pw, u32 capacity);
ndpi_flow_t *ndpi_flow_lookup_or_create4 (ndpi_per_worker_t *pw,
					  const ndpi_flow_key4_t *key,
					  int *created);
ndpi_flow_t *ndpi_flow_lookup_or_create6 (ndpi_per_worker_t *pw,
					  const ndpi_flow_key6_t *key,
					  int *created);
void ndpi_flow_entry_free (ndpi_per_worker_t *pw, ndpi_flow_t *f);

/* ndpi_classify_callback.c */
int  ndpi_register_classify_callback (const char *name,
                                       ndpi_on_flow_classified_fn_t fn,
                                       void *ctx);
void ndpi_unregister_classify_callback (void);

/* ndpi_counters.c */
void ndpi_counters_update (ndpi_per_worker_t *pw, u32 sw_if_index,
			   ndpi_flow_t *f, u32 pkt_bytes);

/* ndpi_stats.c */
void ndpi_stats_init (ndpi_main_t *nm);
extern vlib_node_registration_t ndpi_stats_process_node;

#endif /* __included_vpp_ndpi_h__ */
