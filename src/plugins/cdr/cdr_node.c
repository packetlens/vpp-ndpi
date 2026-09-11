/*
 * cdr_node.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * cdr_node.c - ip4-unicast feature arc node: mirror SIP packets as HEP3.
 *
 * The node runs on every ip4-unicast packet.  For each packet that is:
 *   (a) on a CDR-enabled interface, AND
 *   (b) identified as SIP (via nDPI app_protocol lookup or port heuristic),
 * it builds a HEP3 frame and sends it to the configured Homer server via
 * the pre-connected UDP socket.  Packets are never dropped by this node.
 *
 * nDPI dependency is resolved lazily via dlsym — the CDR plugin works
 * standalone (port heuristic) if vpp-ndpi is not loaded.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <cdr/cdr.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vlib/unix/unix.h>

#include <dlfcn.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

/* ── nDPI symbol stubs (same pattern as ddos_voip.c) ────────────────────── */

typedef struct { u32 src_a, dst_a; u16 sp, dp; u8 proto; u8 pad[3]; }
  _cdr_ndpi_key4_t;

typedef struct
{
  u16 master_protocol;
  u16 app_protocol;
  u16 category;
  u8  classified;
} _cdr_ndpi_flow_stub_t;

typedef struct { void *per_worker; } _cdr_ndpi_main_t;
typedef struct { void *ndpi; void *flow_pool; void *flow_ht; }
  _cdr_ndpi_per_worker_t;
typedef void * (*_cdr_lookup_fn_t)(void *, const _cdr_ndpi_key4_t *, int *);

static_always_inline u16
cdr_get_sip_proto_id (void)
{
  _cdr_ndpi_main_t *nm = dlsym (RTLD_DEFAULT, "ndpi_main");
  if (!nm || !nm->per_worker)
    return CDR_NDPI_SIP_PROTO_ID;

  _cdr_ndpi_per_worker_t *pw = (_cdr_ndpi_per_worker_t *) nm->per_worker;
  if (!pw->ndpi)
    return CDR_NDPI_SIP_PROTO_ID;

  typedef struct { u16 master; u16 app; } _ndpi_proto_t;
  typedef _ndpi_proto_t (*_get_proto_fn_t)(void *, const char *);
  _get_proto_fn_t gp =
    (_get_proto_fn_t) dlsym (RTLD_DEFAULT, "ndpi_get_protocol_by_name");
  if (!gp)
    return CDR_NDPI_SIP_PROTO_ID;

  _ndpi_proto_t p = gp (pw->ndpi, "SIP");
  return p.app ? p.app : CDR_NDPI_SIP_PROTO_ID;
}

static_always_inline u16
cdr_ndpi_app_protocol (u32 thread_index, ip4_header_t *ip0)
{
  static _cdr_ndpi_main_t *nm = NULL;
  static int nm_checked = 0;
  if (PREDICT_FALSE (!nm_checked))
    {
      nm = dlsym (RTLD_DEFAULT, "ndpi_main");
      nm_checked = 1;
    }
  if (PREDICT_FALSE (!nm || !nm->per_worker))
    return 0;

  static _cdr_lookup_fn_t lookup_fn = NULL;
  static int fn_checked = 0;
  if (PREDICT_FALSE (!fn_checked))
    {
      lookup_fn = (_cdr_lookup_fn_t) dlsym (RTLD_DEFAULT,
                                             "ndpi_flow_lookup_or_create4");
      fn_checked = 1;
    }
  if (PREDICT_FALSE (!lookup_fn))
    return 0;

  u8 proto = ip0->protocol;
  u16 sport = 0, dport = 0;
  if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP)
    {
      u8 ihl = (ip0->ip_version_and_header_length & 0x0f) * 4;
      u16 *l4 = (u16 *) ((u8 *) ip0 + ihl);
      sport = clib_net_to_host_u16 (l4[0]);
      dport = clib_net_to_host_u16 (l4[1]);
    }

  _cdr_ndpi_key4_t k = { 0 };
  k.src_a = ip0->src_address.as_u32;
  k.dst_a = ip0->dst_address.as_u32;
  k.sp    = sport;
  k.dp    = dport;
  k.proto = proto;

  _cdr_ndpi_per_worker_t *pw =
    (_cdr_ndpi_per_worker_t *) nm->per_worker + thread_index;

  int created = 0;
  _cdr_ndpi_flow_stub_t *f =
    (_cdr_ndpi_flow_stub_t *) lookup_fn (pw, &k, &created);
  return (f && f->classified) ? f->app_protocol : 0;
}

/* ── SIP heuristic (fallback when nDPI not loaded) ───────────────────────── */

static_always_inline int
cdr_payload_is_sip (const u8 *data, u16 len)
{
  if (len < 7)
    return 0;
  if (!clib_memcmp (data, "SIP/2.0", 7))
    return 1;
  /* Common SIP request methods — check most frequent first */
  if (len >= 7  && !clib_memcmp (data, "INVITE ",  7)) return 1;
  if (len >= 4  && !clib_memcmp (data, "BYE ",     4)) return 1;
  if (len >= 4  && !clib_memcmp (data, "ACK ",     4)) return 1;
  if (len >= 9  && !clib_memcmp (data, "REGISTER", 8)) return 1;
  if (len >= 8  && !clib_memcmp (data, "OPTIONS ", 8)) return 1;
  if (len >= 7  && !clib_memcmp (data, "CANCEL ",  7)) return 1;
  if (len >= 7  && !clib_memcmp (data, "NOTIFY ",  7)) return 1;
  if (len >= 10 && !clib_memcmp (data, "SUBSCRIBE", 9)) return 1;
  if (len >= 5  && !clib_memcmp (data, "INFO ",    5)) return 1;
  if (len >= 6  && !clib_memcmp (data, "REFER ",   6)) return 1;
  if (len >= 7  && !clib_memcmp (data, "UPDATE ",  7)) return 1;
  if (len >= 6  && !clib_memcmp (data, "PRACK ",   6)) return 1;
  return 0;
}

static_always_inline int
cdr_is_sip_port (u16 port_net)
{
  u16 p = clib_net_to_host_u16 (port_net);
  return (p == CDR_SIP_PORT_1 || p == CDR_SIP_PORT_2);
}

/* ── L7 payload extraction ───────────────────────────────────────────────── */

static_always_inline u8 *
cdr_extract_l7 (vlib_buffer_t *b0, ip4_header_t *ip0,
                u16 *src_port_out, u16 *dst_port_out, u16 *l7_len_out)
{
  u8  ihl   = (ip0->ip_version_and_header_length & 0x0f) * 4;
  u16 iplen = clib_net_to_host_u16 (ip0->length);
  u8  proto = ip0->protocol;

  if (ihl > iplen || ihl < 20)
    return NULL;

  u16 buf_ip_span = clib_min ((u16) b0->current_length, iplen);
  u8 *l4    = (u8 *) ip0 + ihl;
  u16 l4_len = buf_ip_span - ihl;

  u8  *payload;
  u16  payload_len;
  u16  sport_net, dport_net;

  if (proto == IP_PROTOCOL_UDP)
    {
      if (l4_len < 8)
        return NULL;
      udp_header_t *udp = (udp_header_t *) l4;
      sport_net   = udp->src_port;
      dport_net   = udp->dst_port;
      u16 udp_len = clib_net_to_host_u16 (udp->length);
      if (udp_len < 8)
        return NULL;
      payload     = l4 + sizeof (udp_header_t);
      payload_len = clib_min ((u16)(udp_len - 8), (u16)(l4_len - 8));
    }
  else if (proto == IP_PROTOCOL_TCP)
    {
      if (l4_len < 20)
        return NULL;
      tcp_header_t *tcp = (tcp_header_t *) l4;
      sport_net   = tcp->src_port;
      dport_net   = tcp->dst_port;
      u8 tcp_hlen = tcp_doff (tcp) * 4;
      if (tcp_hlen < 20 || tcp_hlen > l4_len)
        return NULL;
      payload     = l4 + tcp_hlen;
      payload_len = l4_len - tcp_hlen;
    }
  else
    return NULL;

  if (!payload_len)
    return NULL;

  *src_port_out = sport_net;
  *dst_port_out = dport_net;
  *l7_len_out   = payload_len;
  return payload;
}

/* ── Error counters ──────────────────────────────────────────────────────── */

#define foreach_cdr_error \
  _(MIRRORED,   "SIP packets mirrored to Homer") \
  _(SEND_FAIL,  "HEP3 send failures")            \
  _(NO_HEP,     "Homer not configured")

typedef enum
{
#define _(sym, str) CDR_ERROR_##sym,
  foreach_cdr_error
#undef _
  CDR_N_ERROR,
} cdr_error_t;

static char *cdr_error_strings[] = {
#define _(sym, str) str,
  foreach_cdr_error
#undef _
};

/* ── Next index ──────────────────────────────────────────────────────────── */

typedef enum
{
  CDR_NEXT_PASS = 0,
  CDR_N_NEXT,
} cdr_next_t;

/* ── Node function ───────────────────────────────────────────────────────── */

VLIB_NODE_FN (cdr_observe_node) (vlib_main_t *vm,
                                  vlib_node_runtime_t *node,
                                  vlib_frame_t *frame)
{
  cdr_main_t *cm = &cdr_main;
  u32 thread_index = vm->thread_index;

  /* Lazy-resolve nDPI SIP protocol ID on first call */
  if (PREDICT_FALSE (!cm->sip_proto_id))
    cm->sip_proto_id = cdr_get_sip_proto_id ();

  u8 hep_buf[CDR_HEP3_MAX_FRAME];

  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;

  from        = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0 = from[0];
          from++;
          n_left_from--;

          vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

          /* This node is observe-only — always pass to the next feature */
          u32 next0 = CDR_NEXT_PASS;
          vnet_feature_next (&next0, b0);

          to_next[0] = bi0;
          to_next++;
          n_left_to_next--;

          /* ── SIP detection ─────────────────────────────────────────── */

          ip4_header_t *ip0 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE ((ip0->ip_version_and_header_length >> 4) != 4))
            goto enqueue0;

          u16 sport_net, dport_net, l7_len;
          u8 *payload = cdr_extract_l7 (b0, ip0, &sport_net, &dport_net,
                                        &l7_len);
          if (PREDICT_FALSE (!payload))
            goto enqueue0;

          /* Identify SIP via nDPI first, fall back to port+payload heuristic */
          int is_sip = 0;
          u16 app_id = cdr_ndpi_app_protocol (thread_index, ip0);
          if (PREDICT_TRUE (app_id))
            {
              is_sip = (app_id == cm->sip_proto_id);
            }
          else
            {
              if ((cdr_is_sip_port (sport_net) || cdr_is_sip_port (dport_net))
                  && (ip0->protocol == IP_PROTOCOL_UDP ||
                      ip0->protocol == IP_PROTOCOL_TCP))
                is_sip = cdr_payload_is_sip (payload, l7_len);
            }

          if (!is_sip)
            goto enqueue0;

          /* ── Send HEP3 to Homer ─────────────────────────────────────── */

          if (PREDICT_FALSE (!cm->homer_ip4))
            {
              vlib_node_increment_counter (vm, node->node_index,
                                           CDR_ERROR_NO_HEP, 1);
              cm->pkts_not_configured++;
              goto enqueue0;
            }

          if (PREDICT_FALSE (cm->hep_sock < 0))
            cdr_hep_sock_open (cm);

          if (PREDICT_FALSE (cm->hep_sock < 0))
            {
              cm->pkts_failed++;
              goto enqueue0;
            }

          f64 now = unix_time_now ();
          u32 ts_sec  = (u32) now;
          u32 ts_usec = (u32) ((now - (f64) ts_sec) * 1e6);

          u16 mirror_len = clib_min (l7_len, (u16) CDR_HEP3_MAX_PAYLOAD);

          int hep_len = cdr_build_hep3 (
            hep_buf, (int) sizeof (hep_buf),
            ip0->src_address.as_u32, ip0->dst_address.as_u32,
            sport_net, dport_net,
            ip0->protocol,
            ts_sec, ts_usec,
            cm->capture_agent_id,
            cm->hep_password, (u16) vec_len (cm->hep_password),
            payload, mirror_len);

          if (PREDICT_FALSE (hep_len < 0))
            {
              cm->pkts_failed++;
              goto enqueue0;
            }

          ssize_t sent = send (cm->hep_sock, hep_buf, hep_len, MSG_DONTWAIT);
          if (PREDICT_FALSE (sent < 0))
            {
              vlib_node_increment_counter (vm, node->node_index,
                                           CDR_ERROR_SEND_FAIL, 1);
              cm->pkts_failed++;
              goto enqueue0;
            }

          vlib_node_increment_counter (vm, node->node_index,
                                       CDR_ERROR_MIRRORED, 1);
          cm->pkts_mirrored++;

        enqueue0:
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                            to_next, n_left_to_next,
                                            bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* ── Node and feature registration ──────────────────────────────────────── */

VLIB_REGISTER_NODE (cdr_observe_node) = {
  .name          = "cdr-observe",
  .vector_size   = sizeof (u32),
  .type          = VLIB_NODE_TYPE_INTERNAL,
  .n_errors      = CDR_N_ERROR,
  .error_strings = cdr_error_strings,
  .n_next_nodes  = CDR_N_NEXT,
  .next_nodes    = {
    [CDR_NEXT_PASS] = "ip4-lookup",
  },
};

VNET_FEATURE_INIT (cdr_observe_ip4, static) = {
  .arc_name    = "ip4-unicast",
  .node_name   = "cdr-observe",
  .runs_after  = VNET_FEATURES ("ndpi-observe"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
