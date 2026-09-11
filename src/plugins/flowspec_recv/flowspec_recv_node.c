/*
 * flowspec_recv_node.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * flowspec_recv_node.c - vpp-flowspec-recv data-plane enforcement node.
 *
 * Feature arc: ip4-unicast.  For each IPv4 packet:
 *   1. Extract the destination address.
 *   2. Linear scan of fm->rules for the longest-matching prefix.
 *   3. If matched and action=DROP: send to error-drop.
 *      If matched and action=RATE_LIMIT: apply the token-bucket policer;
 *        drops excess packets, lets conforming packets continue.
 *   4. No match: vnet_feature_next() — continue the arc unchanged.
 *
 * The rule vec is written only by the process node (under worker barrier),
 * so reads here are safe without locks.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <flowspec_recv/flowspec_recv.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/format.h>
#include <vppinfra/time.h>

VNET_FEATURE_INIT (flowspec_recv_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "flowspec-recv",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

typedef enum
{
  FLOWSPEC_RECV_NEXT_PASS = 0,
  FLOWSPEC_RECV_NEXT_DROP,
  FLOWSPEC_RECV_N_NEXT,
} flowspec_recv_next_t;

#define foreach_flowspec_recv_error                                           \
  _ (PASS,         "packets passed (no rule match)")                          \
  _ (DROPPED,      "packets dropped (FlowSpec drop rule)")                    \
  _ (RATE_LIMITED, "packets dropped (FlowSpec rate-limit exceed)")            \
  _ (CONFORMED,    "packets rate-limited and conformed")

typedef enum
{
#define _(sym, str) FLOWSPEC_RECV_ERROR_##sym,
  foreach_flowspec_recv_error
#undef _
    FLOWSPEC_RECV_N_ERROR,
} flowspec_recv_error_t;

static char *flowspec_recv_error_strings[] = {
#define _(sym, str) str,
  foreach_flowspec_recv_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  ip4_address_t dst;
  u8  matched;
  u8  action;
} flowspec_recv_trace_t;

static u8 *
format_flowspec_recv_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowspec_recv_trace_t *t = va_arg (*args, flowspec_recv_trace_t *);
  const char *action_str = !t->matched ? "pass" :
    (t->action == FLOWSPEC_RECV_ACTION_RATE_LIMIT ? "rate-limit" : "drop");
  s = format (s, "flowspec-recv: sw_if %u dst %U matched=%u action=%s",
	      t->sw_if_index, format_ip4_address, &t->dst,
	      t->matched, action_str);
  return s;
}

/* Return the best-matching rule (longest prefix) for dst, or NULL. */
static flowspec_recv_rule_t *
frr_lpm_lookup (flowspec_recv_main_t *fm, ip4_address_t *dst)
{
  flowspec_recv_rule_t *best = NULL;
  flowspec_recv_rule_t *r;

  vec_foreach (r, fm->rules)
    {
      if (!r->valid)
	continue;

      /* Build mask from prefix_len. */
      u32 mask = (r->prefix_len == 0) ? 0 :
	clib_host_to_net_u32 (~0u << (32 - r->prefix_len));

      if ((dst->as_u32 & mask) == (r->dst.as_u32 & mask))
	{
	  if (!best || r->prefix_len > best->prefix_len)
	    best = r;
	}
    }

  return best;
}

static uword
flowspec_recv_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  flowspec_recv_main_t *fm = &flowspec_recv_main;
  vnet_policer_main_t *vpm = &vnet_policer_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 n_pass = 0, n_drop = 0, n_exceed = 0, n_conform = 0;

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
	  u32 next0 = FLOWSPEC_RECV_NEXT_PASS;
	  u8 matched = 0;
	  u8 action = 0;

	  from += 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  if (n_left_from > 0)
	    {
	      vlib_buffer_t *nb = vlib_get_buffer (vm, from[0]);
	      clib_prefetch_load (nb);
	      CLIB_PREFETCH (nb->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	  u8 version = ip0->ip_version_and_header_length >> 4;

	  if (PREDICT_TRUE (version == 4))
	    {
	      flowspec_recv_rule_t *rule =
		frr_lpm_lookup (fm, &ip0->dst_address);

	      if (rule)
		{
		  matched = 1;
		  action = rule->action;

		  if (action == FLOWSPEC_RECV_ACTION_DROP)
		    {
		      next0 = FLOWSPEC_RECV_NEXT_DROP;
		      b0->error = node->errors[FLOWSPEC_RECV_ERROR_DROPPED];
		      n_drop++;
		      fm->pkts_dropped++;
		    }
		  else /* RATE_LIMIT */
		    {
		      if (rule->pol_index != ~0u)
			{
			  policer_t *policer =
			    pool_elt_at_index (vpm->policers, rule->pol_index);
			  u32 pkt_len =
			    vlib_buffer_length_in_chain (vm, b0);
			  u32 result =
			    vnet_police_packet (policer, pkt_len,
						POLICE_CONFORM,
						clib_cpu_time_now ());
			  if (result != POLICE_CONFORM)
			    {
			      next0 = FLOWSPEC_RECV_NEXT_DROP;
			      b0->error =
				node->errors[FLOWSPEC_RECV_ERROR_RATE_LIMITED];
			      n_exceed++;
			      fm->pkts_rate_limited++;
			    }
			  else
			    {
			      n_conform++;
			    }
			}
		      else
			{
			  /* Policer allocation failed earlier — fall through. */
			}
		    }
		}
	      else
		{
		  n_pass++;
		}
	    }

	  if (next0 == FLOWSPEC_RECV_NEXT_PASS)
	    vnet_feature_next (&next0, b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      flowspec_recv_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index;
	      t->dst = ip0->dst_address;
	      t->matched = matched;
	      t->action = action;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       FLOWSPEC_RECV_ERROR_PASS, n_pass);
  vlib_node_increment_counter (vm, node->node_index,
			       FLOWSPEC_RECV_ERROR_DROPPED, n_drop);
  vlib_node_increment_counter (vm, node->node_index,
			       FLOWSPEC_RECV_ERROR_RATE_LIMITED, n_exceed);
  vlib_node_increment_counter (vm, node->node_index,
			       FLOWSPEC_RECV_ERROR_CONFORMED, n_conform);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (flowspec_recv_node) = {
  .function = flowspec_recv_node_fn,
  .name = "flowspec-recv",
  .vector_size = sizeof (u32),
  .format_trace = format_flowspec_recv_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FLOWSPEC_RECV_N_ERROR,
  .error_strings = flowspec_recv_error_strings,
  .n_next_nodes = FLOWSPEC_RECV_N_NEXT,
  .next_nodes = {
    [FLOWSPEC_RECV_NEXT_PASS] = "ip4-lookup",
    [FLOWSPEC_RECV_NEXT_DROP] = "error-drop",
  },
};
