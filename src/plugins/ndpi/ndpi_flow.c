/*
 * ndpi_flow.c - Per-worker flow table (bihash + pool).
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <ndpi/ndpi.h>

int
ndpi_flow_table_init (ndpi_per_worker_t *pw, u32 capacity)
{
  if (capacity < 1024)
    capacity = 1024;

  /* Bihash sized for roughly the requested capacity with a ~50% load
   * factor. Memory is ~64 B * buckets for v4, larger for v6. */
  u32 buckets = capacity / 4;
  if (buckets < 256)
    buckets = 256;

  clib_bihash_init_16_8 (&pw->flow_ht4, "ndpi-flow-v4", buckets,
			 64ULL << 20 /* 64 MB */);
  clib_bihash_init_48_8 (&pw->flow_ht6, "ndpi-flow-v6", buckets,
			 64ULL << 20 /* 64 MB */);
  return 0;
}

static void
ndpi_flow_entry_reset (ndpi_flow_t *f)
{
  f->master_protocol = 0;
  f->app_protocol = 0;
  f->category = 0;
  f->classified = 0;
  f->give_up_count = 0;
  f->ndpi_flow = NULL;
  f->sni[0] = 0;
  f->ja3_hash[0] = 0;
  f->packet_count = 0;
  f->byte_count = 0;
  f->first_seen = 0;
  f->last_seen = 0;
  f->interface_index = ~0;
}

static ndpi_flow_t *
ndpi_flow_alloc_entry (ndpi_per_worker_t *pw)
{
  ndpi_flow_t *f;
  pool_get (pw->flows, f);
  clib_memset (f, 0, sizeof (*f));
  ndpi_flow_entry_reset (f);

  u32 sz = ndpi_detection_get_sizeof_ndpi_flow_struct ();
  f->ndpi_flow = clib_mem_alloc (sz);
  clib_memset (f->ndpi_flow, 0, sz);

  f->first_seen = vlib_time_now (ndpi_main.vlib_main);
  f->last_seen = f->first_seen;
  pw->flows_created++;
  return f;
}

void
ndpi_flow_entry_free (ndpi_per_worker_t *pw, ndpi_flow_t *f)
{
  if (f->ndpi_flow)
    {
      /* ndpi_flow_free() is the nDPI-side flow destructor. It tears down
       * the internal state *and* frees the top-level struct via the
       * callback registered with set_ndpi_flow_free() (our clib_mem_free).
       * Do NOT also call clib_mem_free here - that would double-free. */
      ndpi_flow_free (f->ndpi_flow);
      f->ndpi_flow = NULL;
    }
  (void) pw;
}

ndpi_flow_t *
ndpi_flow_lookup_or_create4 (ndpi_per_worker_t *pw,
			     const ndpi_flow_key4_t *key, int *created)
{
  clib_bihash_kv_16_8_t kv;
  clib_memcpy (&kv.key, key, sizeof (*key));

  if (clib_bihash_search_16_8 (&pw->flow_ht4, &kv, &kv) == 0)
    {
      *created = 0;
      return pool_elt_at_index (pw->flows, (u32) kv.value);
    }

  ndpi_flow_t *f = ndpi_flow_alloc_entry (pw);
  f->is_ip6 = 0;
  clib_memcpy (&f->key4, key, sizeof (*key));
  clib_memcpy (&kv.key, key, sizeof (*key));
  kv.value = (u64) (f - pw->flows);
  clib_bihash_add_del_16_8 (&pw->flow_ht4, &kv, 1 /* is_add */);
  *created = 1;
  return f;
}

ndpi_flow_t *
ndpi_flow_lookup_or_create6 (ndpi_per_worker_t *pw,
			     const ndpi_flow_key6_t *key, int *created)
{
  clib_bihash_kv_48_8_t kv;
  clib_memcpy (&kv.key, key, sizeof (*key));

  if (clib_bihash_search_48_8 (&pw->flow_ht6, &kv, &kv) == 0)
    {
      *created = 0;
      return pool_elt_at_index (pw->flows, (u32) kv.value);
    }

  ndpi_flow_t *f = ndpi_flow_alloc_entry (pw);
  f->is_ip6 = 1;
  clib_memcpy (&f->key6, key, sizeof (*key));
  clib_memcpy (&kv.key, key, sizeof (*key));
  kv.value = (u64) (f - pw->flows);
  clib_bihash_add_del_48_8 (&pw->flow_ht6, &kv, 1 /* is_add */);
  *created = 1;
  return f;
}
