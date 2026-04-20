/*
 * ndpi_counters.c - Per-worker, per-interface, per-app counter aggregation.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <ndpi/ndpi.h>

static void
ndpi_counters_ensure (ndpi_per_worker_t *pw, u32 sw_if_index)
{
  vec_validate (pw->app_counters_by_intf, sw_if_index);
  vec_validate (pw->cat_counters_by_intf, sw_if_index);

  ndpi_app_counters_t *ac =
    vec_elt_at_index (pw->app_counters_by_intf, sw_if_index);
  if (vec_len (ac->packets) < NDPI_MAX_SUPPORTED_PROTOCOLS)
    {
      vec_validate (ac->packets, NDPI_MAX_SUPPORTED_PROTOCOLS - 1);
      vec_validate (ac->bytes, NDPI_MAX_SUPPORTED_PROTOCOLS - 1);
      vec_validate (ac->flows, NDPI_MAX_SUPPORTED_PROTOCOLS - 1);
    }

  ndpi_cat_counters_t *cc =
    vec_elt_at_index (pw->cat_counters_by_intf, sw_if_index);
  if (vec_len (cc->packets) < NDPI_PROTOCOL_NUM_CATEGORIES)
    {
      vec_validate (cc->packets, NDPI_PROTOCOL_NUM_CATEGORIES - 1);
      vec_validate (cc->bytes, NDPI_PROTOCOL_NUM_CATEGORIES - 1);
      vec_validate (cc->flows, NDPI_PROTOCOL_NUM_CATEGORIES - 1);
    }
}

void
ndpi_counters_update (ndpi_per_worker_t *pw, u32 sw_if_index, ndpi_flow_t *f,
		      u32 pkt_bytes)
{
  if (PREDICT_FALSE (sw_if_index >= vec_len (pw->app_counters_by_intf) ||
		     vec_len (pw->app_counters_by_intf) == 0))
    ndpi_counters_ensure (pw, sw_if_index);

  u16 app = f->app_protocol ? f->app_protocol : f->master_protocol;
  u16 cat = f->category;

  ndpi_app_counters_t *ac =
    vec_elt_at_index (pw->app_counters_by_intf, sw_if_index);
  if (app < vec_len (ac->packets))
    {
      ac->packets[app] += 1;
      ac->bytes[app] += pkt_bytes;
      if (f->packet_count == 1)
	ac->flows[app] += 1;
    }

  ndpi_cat_counters_t *cc =
    vec_elt_at_index (pw->cat_counters_by_intf, sw_if_index);
  if (cat < vec_len (cc->packets))
    {
      cc->packets[cat] += 1;
      cc->bytes[cat] += pkt_bytes;
      if (f->packet_count == 1)
	cc->flows[cat] += 1;
    }
}
