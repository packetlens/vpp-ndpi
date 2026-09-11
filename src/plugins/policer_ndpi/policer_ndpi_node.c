/*
 * policer_ndpi_node.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policer_ndpi_node.c - vpp-policer-ndpi data-plane enforcement node.
 *
 * Feature arc: ip4-unicast, runs after ndpi-policy, before ip4-lookup.
 * For each classified IPv4 packet:
 *   1. Look up the flow entry (already created by ndpi-observe).
 *   2. If classified and a policer exists for app_protocol, call
 *      vnet_police_packet().
 *   3. If CONFORM: vnet_feature_next() — continue the arc.
 *   4. If EXCEED/VIOLATE: drop (→ error-drop) or DSCP-mark + continue.
 *
 * Unclassified flows and non-IPv4 traffic pass through unchanged.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vppinfra/time.h>
#include <policer_ndpi/policer_ndpi.h>

VNET_FEATURE_INIT (ndpi_policer_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ndpi-policer",
  .runs_after = VNET_FEATURES ("ndpi-policy"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

typedef enum
{
  POLICER_NDPI_NEXT_PASS = 0,
  POLICER_NDPI_NEXT_DROP,
  POLICER_NDPI_N_NEXT,
} policer_ndpi_next_t;

#define foreach_policer_ndpi_error                                            \
  _ (CONFORM, "packets within rate limit")                                    \
  _ (EXCEED, "packets exceeding rate limit (dropped)")                        \
  _ (DSCP_MARKED, "packets exceeding rate limit (DSCP-marked)")               \
  _ (UNCLASSIFIED, "unclassified packets (passed through)")

typedef enum
{
#define _(sym, str) POLICER_NDPI_ERROR_##sym,
  foreach_policer_ndpi_error
#undef _
    POLICER_NDPI_N_ERROR,
} policer_ndpi_error_t;

static char *policer_ndpi_error_strings[] = {
#define _(sym, str) str,
  foreach_policer_ndpi_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  u16 app_id;
  u8 classified;
  u8 result; /* POLICE_CONFORM / POLICE_EXCEED / POLICE_VIOLATE */
} policer_ndpi_trace_t;

static u8 *
format_policer_ndpi_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policer_ndpi_trace_t *t = va_arg (*args, policer_ndpi_trace_t *);
  static const char *result_str[] = { "conform", "exceed", "violate" };
  s = format (s, "ndpi-policer: sw_if %u app_id=%u classified=%u result=%s",
	      t->sw_if_index, t->app_id, t->classified,
	      (t->result < 3) ? result_str[t->result] : "?");
  return s;
}

static uword
ndpi_policer_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame)
{
  policer_ndpi_main_t *pm = &policer_ndpi_main;
  ndpi_main_t *nm = &ndpi_main;
  vnet_policer_main_t *vpm = &vnet_policer_main;
  u32 thread_index = vm->thread_index;
  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, thread_index);
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 n_conform = 0, n_exceed = 0, n_dscp = 0, n_unclassified = 0;

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
	  u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  u32 next0 = POLICER_NDPI_NEXT_PASS;
	  u16 app_id = 0;
	  u8 classified = 0;
	  u8 result = POLICE_CONFORM;

	  from += 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  if (n_left_from > 0)
	    {
	      vlib_buffer_t *nb = vlib_get_buffer (vm, from[0]);
	      clib_prefetch_load (nb);
	      CLIB_PREFETCH (nb->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	  u8 version = ip0->ip_version_and_header_length >> 4;

	  if (PREDICT_TRUE (version == 4))
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

	      int created = 0;
	      ndpi_flow_t *f = ndpi_flow_lookup_or_create4 (pw, &k, &created);
	      if (f)
		{
		  classified = f->classified;
		  app_id = f->app_protocol;

		  if (classified && app_id < vec_len (pm->app_policers) &&
		      pm->app_policers[app_id].valid)
		    {
		      policer_ndpi_app_t *ap = &pm->app_policers[app_id];
		      policer_t *policer =
			pool_elt_at_index (vpm->policers, ap->policer_index);

		      u32 pkt_len = vlib_buffer_length_in_chain (vm, b0);
		      result = vnet_police_packet (policer, pkt_len,
						   POLICE_CONFORM,
						   clib_cpu_time_now ());

		      if (result != POLICE_CONFORM)
			{
			  if (ap->exceed_action == POLICER_NDPI_ACTION_DSCP_MARK)
			    {
			      /* Mark DSCP in IPv4 ToS field and pass. */
			      ip0->tos =
				(ip0->tos & 0x03) | (ap->dscp << 2);
			      /* Recompute checksum. */
			      ip0->checksum = 0;
			      ip0->checksum = ip4_header_checksum (ip0);
			      n_dscp++;
			    }
			  else
			    {
			      /* Drop. */
			      next0 = POLICER_NDPI_NEXT_DROP;
			      b0->error =
				node->errors[POLICER_NDPI_ERROR_EXCEED];
			      n_exceed++;
			    }
			}
		      else
			{
			  n_conform++;
			}
		    }
		  else if (!classified)
		    {
		      n_unclassified++;
		    }
		}
	    }

	  if (next0 == POLICER_NDPI_NEXT_PASS)
	    vnet_feature_next (&next0, b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      policer_ndpi_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index;
	      t->app_id = app_id;
	      t->classified = classified;
	      t->result = result;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_NDPI_ERROR_CONFORM, n_conform);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_NDPI_ERROR_EXCEED, n_exceed);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_NDPI_ERROR_DSCP_MARKED, n_dscp);
  vlib_node_increment_counter (vm, node->node_index,
			       POLICER_NDPI_ERROR_UNCLASSIFIED, n_unclassified);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ndpi_policer_node) = {
  .function = ndpi_policer_node_fn,
  .name = "ndpi-policer",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_ndpi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = POLICER_NDPI_N_ERROR,
  .error_strings = policer_ndpi_error_strings,
  .n_next_nodes = POLICER_NDPI_N_NEXT,
  .next_nodes = {
    [POLICER_NDPI_NEXT_PASS] = "ip4-lookup",
    [POLICER_NDPI_NEXT_DROP] = "error-drop",
  },
};
