/*
 * ipfix.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * ipfix.c - vpp-ipfix plugin init and lifecycle.
 *
 * Registers as a flow-expiry consumer with vpp-ndpi. When ndpi_stats_process
 * expires a flow, our callback appends the record to ipfix_main.pending.
 * The ipfix-export-process node drains pending every 100 ms and sends IPFIX
 * PDUs over UDP to configured collectors.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <ipfix/ipfix.h>
#include <ndpi/ndpi.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

ipfix_main_t ipfix_main;

/* Maximum number of pending records before we start dropping. */
#define IPFIX_PENDING_MAX 16384

/* ---------------------------------------------------------------------------
 * Flow-expiry callback: called from ndpi_stats_process under worker barrier.
 * Copies the expired flow into ipfix_main.pending for later export.
 * ---------------------------------------------------------------------------*/
static void
ipfix_flow_expired_cb (ndpi_per_worker_t *pw, const ndpi_flow_t *f,
		       void *opaque)
{
  ipfix_main_t *im = opaque;

  if (!im->enabled || im->n_collectors == 0)
    return;

  /* Drop if backlog is too large (collector unreachable). */
  if (vec_len (im->pending) >= IPFIX_PENDING_MAX)
    {
      im->ring_overflow_drops++;
      return;
    }

  /* IPv6 not yet supported — skip silently. */
  if (f->is_ip6)
    return;

  ipfix_record_v4_t *r;
  vec_add2 (im->pending, r, 1);
  clib_memset (r, 0, sizeof (*r));

  r->src4 = f->key4.src;
  r->dst4 = f->key4.dst;
  r->src_port = f->key4.src_port;
  r->dst_port = f->key4.dst_port;
  r->protocol = f->key4.proto;

  r->byte_count = f->byte_count;
  r->packet_count = f->packet_count;
  /* Convert VPP monotonic time (seconds since VPP start) to Unix epoch ms
   * by adding the offset computed at plugin init. */
  r->first_seen_ms = (u64) ((f->first_seen + im->unix_epoch_offset) * 1000.0);
  r->last_seen_ms = (u64) ((f->last_seen + im->unix_epoch_offset) * 1000.0);
  r->interface_index = f->interface_index;

  r->app_protocol = f->app_protocol;
  r->category = (u8) f->category;
  r->risk = 0; /* risk bitmask — populated if added to ndpi_flow_t later */

  /* Application name */
  const char *name = ndpi_app_name_for_id (pw, f->app_protocol);
  if (name)
    {
      size_t n = strnlen (name, IPFIX_APP_NAME_LEN - 1);
      clib_memcpy (r->app_name, name, n);
    }

  /* SNI and JA3 */
  if (f->sni[0])
    {
      size_t n = strnlen ((const char *) f->sni, IPFIX_SNI_LEN - 1);
      clib_memcpy (r->sni, f->sni, n);
    }
  if (f->ja3_hash[0])
    {
      size_t n = strnlen ((const char *) f->ja3_hash, IPFIX_JA3_LEN - 1);
      clib_memcpy (r->ja3_hash, f->ja3_hash, n);
    }
}

/* ---------------------------------------------------------------------------
 * Public API: add/remove collectors, enable/disable.
 * ---------------------------------------------------------------------------*/
int
ipfix_exporter_add (ip4_address_t *collector_ip, u16 port,
		    ip4_address_t *src_ip)
{
  ipfix_main_t *im = &ipfix_main;

  /* Replace existing entry for same IP:port. */
  for (u32 i = 0; i < im->n_collectors; i++)
    {
      if (im->collectors[i].ip.as_u32 == collector_ip->as_u32 &&
	  im->collectors[i].port == port)
	{
	  /* Already present. */
	  return 0;
	}
    }

  if (im->n_collectors >= IPFIX_MAX_COLLECTORS)
    return VNET_API_ERROR_TABLE_TOO_BIG;

  ipfix_collector_t *c = &im->collectors[im->n_collectors++];
  c->ip = *collector_ip;
  c->port = port;

  /* Open UDP socket for this collector. */
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      im->n_collectors--;
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (src_ip && src_ip->as_u32 != 0)
    {
      struct sockaddr_in sa = { 0 };
      sa.sin_family = AF_INET;
      sa.sin_addr.s_addr = src_ip->as_u32;
      sa.sin_port = 0;
      bind (fd, (struct sockaddr *) &sa, sizeof (sa));
      im->src_ip = *src_ip;
    }

  c->fd = fd;
  vlib_log_info (im->log_class, "collector added %U:%u",
		 format_ip4_address, collector_ip, port);
  return 0;
}

void
ipfix_exporter_del_all (void)
{
  ipfix_main_t *im = &ipfix_main;
  for (u32 i = 0; i < im->n_collectors; i++)
    {
      if (im->collectors[i].fd >= 0)
	close (im->collectors[i].fd);
      im->collectors[i].fd = -1;
    }
  im->n_collectors = 0;
  im->enabled = 0;
}

int
ipfix_enable_disable (int enable)
{
  ipfix_main_t *im = &ipfix_main;
  im->enabled = enable ? 1 : 0;
  vlib_log_info (im->log_class, "IPFIX export %s",
		 enable ? "enabled" : "disabled");
  return 0;
}

/* ---------------------------------------------------------------------------
 * ipfix-export-process: wakes every 100 ms, drains pending records, sends
 * IPFIX PDUs to all configured collectors.
 * ---------------------------------------------------------------------------*/
static uword
ipfix_export_process_fn (vlib_main_t *vm, vlib_node_runtime_t *rt,
			 vlib_frame_t *frame)
{
  ipfix_main_t *im = &ipfix_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 0.1 /* 100 ms */);
      vlib_process_get_events (vm, 0);

      if (!im->enabled || im->n_collectors == 0)
	continue;

      f64 now = vlib_time_now (vm);

      /* Resend templates periodically. */
      if (now - im->last_template_sent >= IPFIX_TEMPLATE_REFRESH ||
	  im->last_template_sent == 0.0)
	{
	  ipfix_send_templates (im, now);
	}

      /* Flush any pending flow records. */
      ipfix_flush_pending (im);
    }
  return 0;
}

VLIB_REGISTER_NODE (ipfix_export_process_node) = {
  .function = ipfix_export_process_fn,
  .name = "ipfix-export-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};

/* ---------------------------------------------------------------------------
 * Plugin init
 * ---------------------------------------------------------------------------*/
static clib_error_t *
ipfix_init (vlib_main_t *vm)
{
  ipfix_main_t *im = &ipfix_main;
  im->vlib_main = vm;
  im->log_class = vlib_log_register_class ("ipfix", 0);
  im->enabled = 0;
  im->n_collectors = 0;
  im->last_template_sent = 0.0;
  /* Compute epoch offset once; vlib_time_now is monotonic from VPP start. */
  im->unix_epoch_offset = (f64) time (NULL) - vlib_time_now (vm);
  for (u32 i = 0; i < IPFIX_MAX_COLLECTORS; i++)
    im->collectors[i].fd = -1;

  /* Both ipfix and ndpi are compiled into the same ndpi_plugin.so. */
  ndpi_main_t *nm = &ndpi_main;
  nm->flow_expire_cb = ipfix_flow_expired_cb;
  nm->flow_expire_cb_opaque = im;

  vlib_log_info (im->log_class, "vpp-ipfix %s initialized", IPFIX_PLUGIN_VERSION);
  return 0;
}

/* Must init after ndpi (which is a VLIB_INIT_FUNCTION). */
VLIB_INIT_FUNCTION (ipfix_init);
