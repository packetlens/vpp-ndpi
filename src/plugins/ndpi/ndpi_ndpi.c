/*
 * ndpi_ndpi.c - Wrapper around the nDPI library.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 */

#include <ndpi/ndpi.h>
#include <ndpi_api.h>
#include <string.h>

static void *
ndpi_vpp_malloc (size_t sz)
{
  return clib_mem_alloc (sz);
}

static void
ndpi_vpp_free (void *p)
{
  if (p)
    clib_mem_free (p);
}

int
ndpi_worker_engine_init (ndpi_per_worker_t *pw)
{
  NDPI_PROTOCOL_BITMASK all;

  set_ndpi_malloc (ndpi_vpp_malloc);
  set_ndpi_free (ndpi_vpp_free);
  set_ndpi_flow_malloc (ndpi_vpp_malloc);
  set_ndpi_flow_free (ndpi_vpp_free);

  pw->ndpi = ndpi_init_detection_module ((ndpi_init_prefs) 0);
  if (pw->ndpi == NULL)
    return -1;

  NDPI_BITMASK_SET_ALL (all);
  ndpi_set_protocol_detection_bitmask2 (pw->ndpi, &all);
  ndpi_finalize_initialization (pw->ndpi);
  return 0;
}

void
ndpi_worker_engine_cleanup (ndpi_per_worker_t *pw)
{
  if (pw->ndpi)
    {
      ndpi_exit_detection_module (pw->ndpi);
      pw->ndpi = NULL;
    }
}

static void
ndpi_extract_metadata (ndpi_flow_t *f)
{
  if (f->ndpi_flow == NULL)
    return;

  if (f->ndpi_flow->host_server_name[0])
    {
      size_t n = strnlen ((const char *) f->ndpi_flow->host_server_name,
			  NDPI_MAX_SNI_LEN - 1);
      clib_memcpy (f->sni, f->ndpi_flow->host_server_name, n);
      f->sni[n] = 0;
    }

  if (f->ndpi_flow->protos.tls_quic.ja3_client[0])
    {
      size_t n =
	strnlen ((const char *) f->ndpi_flow->protos.tls_quic.ja3_client,
		 NDPI_MAX_JA3_LEN - 1);
      clib_memcpy (f->ja3_hash, f->ndpi_flow->protos.tls_quic.ja3_client, n);
      f->ja3_hash[n] = 0;
    }

  /* Extract risk bitmask before the ndpi_flow struct is freed. */
  f->risk = (u64) f->ndpi_flow->risk;
}

void
ndpi_classify_packet (ndpi_per_worker_t *pw, ndpi_flow_t *f, u8 *ip_hdr,
		      u32 ip_len, f64 now)
{
  ndpi_main_t *nm = &ndpi_main;

  if (f->ndpi_flow == NULL || f->classified)
    return;

  ndpi_protocol p = ndpi_detection_process_packet (
    pw->ndpi, f->ndpi_flow, ip_hdr, ip_len, (u64) (now * 1000.0));

  pw->ndpi_calls++;
  f->give_up_count++;

  int done = 0;
  if (p.master_protocol != NDPI_PROTOCOL_UNKNOWN &&
      p.app_protocol != NDPI_PROTOCOL_UNKNOWN)
    {
      done = 1;
    }
  else if (f->give_up_count >= nm->classify_max_pkts ||
	   (now - f->first_seen) >= NDPI_CLASSIFY_TIMEOUT)
    {
      u_int8_t guessed = 0;
      p = ndpi_detection_giveup (pw->ndpi, f->ndpi_flow,
				 1 /* enable_guess */, &guessed);
      done = 1;
      pw->flows_gave_up++;
    }

  if (done)
    {
      f->master_protocol = p.master_protocol;
      f->app_protocol    = p.app_protocol;
      f->category        = p.category;
      ndpi_extract_metadata (f);  /* also extracts f->risk */
      f->classified = 1;
      pw->flows_classified++;

      /* Fire the classification callback if one is registered.
       * Called before ndpi_flow_entry_free so f->sni/ja3/risk are valid.
       * The callback is re-entrant and must not block. */
      if (PREDICT_FALSE (nm->classify_cb != NULL))
        {
          u32 src4 = 0, dst4 = 0;
          u16 sport = 0, dport = 0;
          u8  proto = 0;

          if (!f->is_ip6)
            {
              src4  = clib_net_to_host_u32 (f->key4.src.as_u32);
              dst4  = clib_net_to_host_u32 (f->key4.dst.as_u32);
              sport = f->key4.src_port;
              dport = f->key4.dst_port;
              proto = f->key4.proto;
            }
          else
            {
              sport = f->key6.src_port;
              dport = f->key6.dst_port;
              proto = f->key6.proto;
            }

          nm->classify_cb (src4, dst4, proto, sport, dport,
                           f->master_protocol, f->app_protocol, f->category,
                           f->risk, f->sni, f->ja3_hash,
                           f->interface_index,
                           nm->classify_cb_ctx);
          nm->classify_cb_calls++;
        }

      /* Release the ~1 KB nDPI flow struct */
      ndpi_flow_entry_free (pw, f);
    }
}

const char *
ndpi_app_name_for_id (ndpi_per_worker_t *pw, u16 app_id)
{
  if (pw == NULL || pw->ndpi == NULL)
    return "Unknown";
  return ndpi_get_proto_name (pw->ndpi, app_id);
}

const char *
ndpi_cat_name_for_id (ndpi_per_worker_t *pw, u16 cat_id)
{
  if (pw == NULL || pw->ndpi == NULL)
    return "Unknown";
  return ndpi_category_get_name (pw->ndpi, (ndpi_protocol_category_t) cat_id);
}
