/*
 * policy_node.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * policy_node.c - vpp-policy data-plane enforcement node.
 *
 * Feature arc: ip4-unicast, runs after ndpi-observe, before ip4-lookup.
 * For each packet:
 *   1. Look up the flow entry (already created by ndpi-observe).
 *   2. If classified, apply the per-app rule (or the default action).
 *   3. Drop (→ error-drop) or pass (→ continue feature arc).
 *
 * Unclassified flows (classification still in progress) are always permitted
 * so that nDPI can finish classifying them.  Non-IPv4 packets pass through.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <policy/policy.h>

VNET_FEATURE_INIT (ndpi_policy_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ndpi-policy",
  .runs_after = VNET_FEATURES ("ndpi-observe"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

typedef enum
{
  POLICY_NEXT_PASS = 0,
  POLICY_NEXT_DROP,
  POLICY_N_NEXT,
} policy_next_t;

#define foreach_policy_error                                                  \
  _ (PERMITTED, "packets permitted by app policy")                            \
  _ (DROPPED, "packets dropped by app policy")                                \
  _ (UNCLASSIFIED, "unclassified packets (permitted)")

typedef enum
{
#define _(sym, str) POLICY_ERROR_##sym,
  foreach_policy_error
#undef _
    POLICY_N_ERROR,
} policy_error_t;

static char *policy_error_strings[] = {
#define _(sym, str) str,
  foreach_policy_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  u16 app_id;
  u8 classified;
  u8 action;
} policy_trace_t;

static u8 *
format_policy_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  policy_trace_t *t = va_arg (*args, policy_trace_t *);
  s = format (s, "ndpi-policy: sw_if %u app_id=%u classified=%u action=%s",
	      t->sw_if_index, t->app_id, t->classified,
	      t->action == POLICY_ACTION_DROP ? "drop" : "permit");
  return s;
}

static uword
ndpi_policy_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame)
{
  policy_main_t *pm = &policy_main;
  ndpi_main_t *nm = &ndpi_main;
  u32 thread_index = vm->thread_index;
  ndpi_per_worker_t *pw = vec_elt_at_index (nm->per_worker, thread_index);
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 n_permitted = 0, n_dropped = 0, n_unclassified = 0;

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
	  u32 next0 = POLICY_NEXT_PASS;
	  u16 app_id = 0;
	  u8 classified = 0;
	  u8 action = POLICY_ACTION_PERMIT; /* default: permit non-IPv4 */

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

		  if (classified)
		    {
		      /* Apply per-app rule, falling back to default_action. */
		      if (app_id < vec_len (pm->app_rules) &&
			  pm->app_rules[app_id].valid)
			action = pm->app_rules[app_id].action;
		      else
			action = pm->default_action;
		    }
		  else
		    {
		      /* Not yet classified: permit so nDPI can finish. */
		      action = POLICY_ACTION_PERMIT;
		      n_unclassified++;
		    }
		}
	      else
		{
		  action = pm->default_action;
		}
	    }

	  if (action == POLICY_ACTION_DROP)
	    {
	      next0 = POLICY_NEXT_DROP;
	      b0->error = node->errors[POLICY_ERROR_DROPPED];
	      n_dropped++;
	    }
	  else
	    {
	      vnet_feature_next (&next0, b0);
	      n_permitted++;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      policy_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index;
	      t->app_id = app_id;
	      t->classified = classified;
	      t->action = action;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, POLICY_ERROR_PERMITTED,
			       n_permitted);
  vlib_node_increment_counter (vm, node->node_index, POLICY_ERROR_DROPPED,
			       n_dropped);
  vlib_node_increment_counter (vm, node->node_index, POLICY_ERROR_UNCLASSIFIED,
			       n_unclassified);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ndpi_policy_node) = {
  .function = ndpi_policy_node_fn,
  .name = "ndpi-policy",
  .vector_size = sizeof (u32),
  .format_trace = format_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = POLICY_N_ERROR,
  .error_strings = policy_error_strings,
  .n_next_nodes = POLICY_N_NEXT,
  .next_nodes = {
    [POLICY_NEXT_PASS] = "ip4-lookup",
    [POLICY_NEXT_DROP] = "error-drop",
  },
};
