/*
 * node_observe.c - Passive observation graph node for vpp-ndpi.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <ndpi/ndpi.h>

VNET_FEATURE_INIT (ndpi_observe_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ndpi-observe",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ndpi_observe_ip6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ndpi-observe",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

typedef struct
{
  u32 sw_if_index;
  u16 app_id;
  u16 master_id;
  u8 classified;
  u8 is_ip6;
} ndpi_trace_t;

static u8 *
format_ndpi_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ndpi_trace_t *t = va_arg (*args, ndpi_trace_t *);
  s = format (s, "ndpi: sw_if %u %s classified=%u master=%u app=%u",
	      t->sw_if_index, t->is_ip6 ? "ip6" : "ip4", t->classified,
	      t->master_id, t->app_id);
  return s;
}

#define foreach_ndpi_error                                                    \
  _ (PROCESSED, "packets processed")                                          \
  _ (CACHED, "cached verdict hits")                                           \
  _ (NEW_FLOW, "new flows")                                                   \
  _ (NOT_IP, "packets not IP (pass-through)")

typedef enum
{
#define _(sym, str) NDPI_ERROR_##sym,
  foreach_ndpi_error
#undef _
    NDPI_N_ERROR,
} ndpi_error_t;

static char *ndpi_error_strings[] = {
#define _(sym, str) str,
  foreach_ndpi_error
#undef _
};

static_always_inline ndpi_flow_t *
ndpi_observe_one_ip4 (ndpi_per_worker_t *pw, ip4_header_t *ip0, u32 ip_len,
		      u32 sw_if_index, u32 pkt_bytes, f64 now, int *created)
{
  u8 proto = ip0->protocol;
  u16 sport = 0, dport = 0;

  if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP)
    {
      u8 ihl = (ip0->ip_version_and_header_length & 0x0f) * 4;
      u16 *l4 = (u16 *) ((u8 *) ip0 + ihl);
      sport = clib_net_to_host_u16 (l4[0]);
      dport = clib_net_to_host_u16 (l4[1]);
    }

  ndpi_flow_key4_t k = { 0 };
  k.src = ip0->src_address;
  k.dst = ip0->dst_address;
  k.src_port = sport;
  k.dst_port = dport;
  k.proto = proto;

  ndpi_flow_t *f = ndpi_flow_lookup_or_create4 (pw, &k, created);
  if (*created)
    {
      f->interface_index = sw_if_index;
      pw->packets_scanned++;
      ndpi_classify_packet (pw, f, (u8 *) ip0, ip_len, now);
    }
  else if (!f->classified)
    {
      pw->packets_scanned++;
      ndpi_classify_packet (pw, f, (u8 *) ip0, ip_len, now);
    }
  else
    {
      pw->packets_cached++;
    }

  f->packet_count++;
  f->byte_count += pkt_bytes;
  f->last_seen = now;
  ndpi_counters_update (pw, sw_if_index, f, pkt_bytes);
  return f;
}

static_always_inline ndpi_flow_t *
ndpi_observe_one_ip6 (ndpi_per_worker_t *pw, ip6_header_t *ip0, u32 ip_len,
		      u32 sw_if_index, u32 pkt_bytes, f64 now, int *created)
{
  u8 proto = ip0->protocol;
  u16 sport = 0, dport = 0;

  if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP)
    {
      u16 *l4 = (u16 *) (ip0 + 1);
      sport = clib_net_to_host_u16 (l4[0]);
      dport = clib_net_to_host_u16 (l4[1]);
    }

  ndpi_flow_key6_t k = { 0 };
  k.src = ip0->src_address;
  k.dst = ip0->dst_address;
  k.src_port = sport;
  k.dst_port = dport;
  k.proto = proto;

  ndpi_flow_t *f = ndpi_flow_lookup_or_create6 (pw, &k, created);
  if (*created)
    {
      f->interface_index = sw_if_index;
      pw->packets_scanned++;
      ndpi_classify_packet (pw, f, (u8 *) ip0, ip_len, now);
    }
  else if (!f->classified)
    {
      pw->packets_scanned++;
      ndpi_classify_packet (pw, f, (u8 *) ip0, ip_len, now);
    }
  else
    {
      pw->packets_cached++;
    }

  f->packet_count++;
  f->byte_count += pkt_bytes;
  f->last_seen = now;
  ndpi_counters_update (pw, sw_if_index, f, pkt_bytes);
  return f;
}

static uword
ndpi_observe_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  ndpi_main_t *nm = &ndpi_main;
  u32 thread_index = vm->thread_index;
  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, thread_index);
  u32 next_index = node->cached_next_index;
  f64 now = vlib_time_now (vm);
  u32 n_processed = 0, n_cached = 0, n_new = 0, n_not_ip = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  u32 next0 = NDPI_NEXT_PASS;
	  ndpi_flow_t *f = NULL;
	  int created = 0;
	  int is_ip6 = 0;

	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *nb = vlib_get_buffer (vm, from[1]);
	      clib_prefetch_load (nb);
	      CLIB_PREFETCH (nb->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	  u8 version = (ip0->ip_version_and_header_length >> 4);
	  u32 pkt_bytes = vlib_buffer_length_in_chain (vm, b0);
	  u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_TRUE (version == 4))
	    {
	      u32 ip_len = clib_net_to_host_u16 (ip0->length);
	      f = ndpi_observe_one_ip4 (pw, ip0, ip_len, sw_if_index,
					pkt_bytes, now, &created);
	    }
	  else if (version == 6)
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) ip0;
	      u32 ip_len =
		clib_net_to_host_u16 (ip6->payload_length) + sizeof (*ip6);
	      is_ip6 = 1;
	      f = ndpi_observe_one_ip6 (pw, ip6, ip_len, sw_if_index,
					pkt_bytes, now, &created);
	    }
	  else
	    {
	      n_not_ip++;
	    }

	  if (f)
	    {
	      n_processed++;
	      if (created)
		n_new++;
	      if (f->classified)
		n_cached++;
	    }

	  vnet_feature_next (&next0, b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ndpi_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index;
	      t->is_ip6 = is_ip6;
	      t->classified = f ? f->classified : 0;
	      t->master_id = f ? f->master_protocol : 0;
	      t->app_id = f ? f->app_protocol : 0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, NDPI_ERROR_PROCESSED,
			       n_processed);
  vlib_node_increment_counter (vm, node->node_index, NDPI_ERROR_CACHED,
			       n_cached);
  vlib_node_increment_counter (vm, node->node_index, NDPI_ERROR_NEW_FLOW,
			       n_new);
  vlib_node_increment_counter (vm, node->node_index, NDPI_ERROR_NOT_IP,
			       n_not_ip);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ndpi_observe_node) = {
  .function = ndpi_observe_node_fn,
  .name = "ndpi-observe",
  .vector_size = sizeof (u32),
  .format_trace = format_ndpi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = NDPI_N_ERROR,
  .error_strings = ndpi_error_strings,
  .n_next_nodes = NDPI_N_NEXT,
  .next_nodes = {
    [NDPI_NEXT_PASS] = "ip4-lookup", /* overridden by feature arc */
  },
};
