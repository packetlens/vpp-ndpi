/*
 * ipfix_export.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * ipfix_export.c - IPFIX PDU assembly and UDP send for vpp-ipfix.
 *
 * Implements RFC 7011 IPFIX over UDP. Uses fixed-length fields for all
 * enterprise IEs (no variable-length encoding), making PDU assembly simple.
 *
 * IPv4 template ID: 256. Field layout:
 *   IANA 8   (4B)  sourceIPv4Address
 *   IANA 12  (4B)  destinationIPv4Address
 *   IANA 4   (1B)  protocolIdentifier
 *   IANA 7   (2B)  sourceTransportPort
 *   IANA 11  (2B)  destinationTransportPort
 *   IANA 1   (8B)  octetDeltaCount
 *   IANA 2   (8B)  packetDeltaCount
 *   IANA 152 (8B)  flowStartMilliseconds
 *   IANA 153 (8B)  flowEndMilliseconds
 *   IANA 10  (4B)  ingressInterface
 *   PEN/57   (2B)  L7_PROTO          — ntop standard: nDPI app protocol ID (nprobe/ntopng)
 *   PEN/58  (32B)  L7_PROTO_NAME     — ntop standard: nDPI app name string (fixed-length)
 *   PEN/82   (1B)  L7_PROTO_CATEGORY — ntop standard: nDPI category ID
 *   PEN/4    (4B)  ndpiRisk          — custom: risk bitmask
 *   PEN/5   (64B)  tlsSni            — custom: TLS SNI string
 *   PEN/6   (33B)  ja3Hash           — custom: JA3 fingerprint
 *
 * Data record size: 4+4+1+2+2+8+8+8+8+4+2+32+1+4+64+33 = 185 bytes
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <ipfix/ipfix.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Wire-format helpers (big-endian)
 * ---------------------------------------------------------------------------*/
static_always_inline u8 *
put_u8 (u8 *p, u8 v)
{
  *p++ = v;
  return p;
}

static_always_inline u8 *
put_u16 (u8 *p, u16 v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
  return p + 2;
}

static_always_inline u8 *
put_u32 (u8 *p, u32 v)
{
  p[0] = (v >> 24) & 0xff;
  p[1] = (v >> 16) & 0xff;
  p[2] = (v >> 8) & 0xff;
  p[3] = v & 0xff;
  return p + 4;
}

static_always_inline u8 *
put_u64 (u8 *p, u64 v)
{
  p = put_u32 (p, (u32) (v >> 32));
  p = put_u32 (p, (u32) v);
  return p;
}

static_always_inline u8 *
put_bytes (u8 *p, const void *src, u32 n)
{
  clib_memcpy (p, src, n);
  return p + n;
}

static_always_inline u8 *
put_fixed_str (u8 *p, const u8 *src, u32 field_len)
{
  u32 src_len = strnlen ((const char *) src, field_len);
  clib_memcpy (p, src, src_len);
  clib_memset (p + src_len, 0, field_len - src_len);
  return p + field_len;
}

/* ---------------------------------------------------------------------------
 * IPFIX message header (RFC 7011 §3.1), 16 bytes.
 * ---------------------------------------------------------------------------*/
static u8 *
write_msg_header (u8 *p, u16 msg_len, u32 export_time, u32 seq_no)
{
  p = put_u16 (p, IPFIX_VERSION);   /* Version = 10           */
  p = put_u16 (p, msg_len);          /* Total message length   */
  p = put_u32 (p, export_time);      /* Export time (unix sec) */
  p = put_u32 (p, seq_no);           /* Sequence number        */
  p = put_u32 (p, 0);                /* Observation domain = 0 */
  return p;
}

/* ---------------------------------------------------------------------------
 * Write an IPFIX Field Specifier.
 * For IANA IEs: 2 bytes IE ID + 2 bytes field length.
 * For enterprise IEs: IE ID with bit 15 set, 2 bytes length, 4 bytes PEN.
 * ---------------------------------------------------------------------------*/
static u8 *
write_ie (u8 *p, u16 ie_id, u16 len, int is_enterprise)
{
  if (is_enterprise)
    {
      p = put_u16 (p, ie_id | 0x8000); /* enterprise bit set */
      p = put_u16 (p, len);
      p = put_u32 (p, IPFIX_NTOP_PEN);
    }
  else
    {
      p = put_u16 (p, ie_id);
      p = put_u16 (p, len);
    }
  return p;
}

/* ---------------------------------------------------------------------------
 * Build IPv4 template set.
 * Returns total bytes written.
 * ---------------------------------------------------------------------------*/
#define IPFIX_V4_FIELD_COUNT 16

static u32
build_template_v4 (u8 *buf, u32 buf_len)
{
  /* Template set header: set_id=2, length=<computed> */
  /* Template record: template_id=256, field_count=16 */
  u32 rec_len = 4                       /* template id + field count */
		+ 10 * 4               /* 10 IANA IEs × 4 bytes */
		+ 6 * 6;               /* 6 enterprise IEs × 6 bytes */
  u32 set_len = 4 + rec_len;            /* set header + record */
  u32 msg_len = 16 + set_len;           /* IPFIX msg header + set */

  if (msg_len > buf_len)
    return 0;

  u8 *p = buf;

  /* IPFIX message header (fill length later — we know it now) */
  p = write_msg_header (p, (u16) msg_len, (u32) time (NULL), 0);

  /* Set header */
  p = put_u16 (p, IPFIX_SET_ID_TEMPLATE); /* set id = 2 */
  p = put_u16 (p, (u16) set_len);

  /* Template record header */
  p = put_u16 (p, IPFIX_TEMPLATE_ID_V4);
  p = put_u16 (p, IPFIX_V4_FIELD_COUNT);

  /* IANA field specifiers */
  p = write_ie (p, 8, 4, 0);    /* sourceIPv4Address */
  p = write_ie (p, 12, 4, 0);   /* destinationIPv4Address */
  p = write_ie (p, 4, 1, 0);    /* protocolIdentifier */
  p = write_ie (p, 7, 2, 0);    /* sourceTransportPort */
  p = write_ie (p, 11, 2, 0);   /* destinationTransportPort */
  p = write_ie (p, 1, 8, 0);    /* octetDeltaCount */
  p = write_ie (p, 2, 8, 0);    /* packetDeltaCount */
  p = write_ie (p, 152, 8, 0);  /* flowStartMilliseconds */
  p = write_ie (p, 153, 8, 0);  /* flowEndMilliseconds */
  p = write_ie (p, 10, 4, 0);   /* ingressInterface */

  /* Enterprise (ntop PEN 35632) field specifiers.
   * IE 57/58/82 are the standard ntop IEs recognized by nprobe and ntopng,
   * enabling application-name display without any custom configuration. */
  p = write_ie (p, 57, 2, 1);               /* L7_PROTO (nDPI app ID) */
  p = write_ie (p, 58, IPFIX_APP_NAME_LEN, 1); /* L7_PROTO_NAME (app name string) */
  p = write_ie (p, 82, 1, 1);               /* L7_PROTO_CATEGORY */
  p = write_ie (p, 4, 4, 1);                /* ndpiRisk (custom) */
  p = write_ie (p, 5, IPFIX_SNI_LEN, 1);    /* tlsSni (custom) */
  p = write_ie (p, 6, IPFIX_JA3_LEN, 1);    /* ja3Hash (custom) */

  ASSERT (p - buf == (ptrdiff_t) msg_len);
  return msg_len;
}

/* Data record size for IPv4 template */
#define IPFIX_V4_DATA_RECORD_BYTES \
  (4 + 4 + 1 + 2 + 2 + 8 + 8 + 8 + 8 + 4 + \
   2 + IPFIX_APP_NAME_LEN + 1 + 4 + IPFIX_SNI_LEN + IPFIX_JA3_LEN)

/* ---------------------------------------------------------------------------
 * Write a single IPv4 data record into buf. Returns bytes written.
 * ---------------------------------------------------------------------------*/
static u32
write_data_record_v4 (u8 *p, const ipfix_record_v4_t *r)
{
  u8 *start = p;

  p = put_bytes (p, &r->src4, 4);
  p = put_bytes (p, &r->dst4, 4);
  p = put_u8 (p, r->protocol);
  p = put_u16 (p, r->src_port);
  p = put_u16 (p, r->dst_port);
  p = put_u64 (p, r->byte_count);
  p = put_u64 (p, r->packet_count);
  p = put_u64 (p, r->first_seen_ms);
  p = put_u64 (p, r->last_seen_ms);
  p = put_u32 (p, r->interface_index);
  p = put_u16 (p, r->app_protocol);
  p = put_fixed_str (p, r->app_name, IPFIX_APP_NAME_LEN);
  p = put_u8 (p, r->category);
  p = put_u32 (p, r->risk);
  p = put_fixed_str (p, r->sni, IPFIX_SNI_LEN);
  p = put_fixed_str (p, r->ja3_hash, IPFIX_JA3_LEN);

  return (u32) (p - start);
}

/* ---------------------------------------------------------------------------
 * Send a buffer to all configured collectors.
 * ---------------------------------------------------------------------------*/
static void
send_to_collectors (ipfix_main_t *im, const u8 *buf, u32 len)
{
  for (u32 i = 0; i < im->n_collectors; i++)
    {
      ipfix_collector_t *c = &im->collectors[i];
      if (c->fd < 0)
	continue;

      struct sockaddr_in dst = { 0 };
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = c->ip.as_u32;
      dst.sin_port = htons (c->port);

      ssize_t sent =
	sendto (c->fd, buf, len, 0, (struct sockaddr *) &dst, sizeof (dst));
      if (sent < 0)
	{
	  im->udp_send_errors++;
	  vlib_log_warn (im->log_class, "sendto %U:%u failed: %d",
			 format_ip4_address, &c->ip, c->port, errno);
	}
      else
	{
	  im->pdus_sent++;
	}
    }
}

/* ---------------------------------------------------------------------------
 * Public: send template sets to all collectors.
 * ---------------------------------------------------------------------------*/
void
ipfix_send_templates (ipfix_main_t *im, f64 now)
{
  u8 buf[512];
  u32 len = build_template_v4 (buf, sizeof (buf));
  if (len == 0)
    return;

  send_to_collectors (im, buf, len);
  im->templates_sent++;
  im->last_template_sent = now;

  vlib_log_debug (im->log_class, "templates sent (%u bytes)", len);
}

/* ---------------------------------------------------------------------------
 * Public: drain pending records, assemble IPFIX data PDUs, send them.
 * ---------------------------------------------------------------------------*/
void
ipfix_flush_pending (ipfix_main_t *im)
{
  if (vec_len (im->pending) == 0)
    return;

  /* PDU buffer: IPFIX message header (16) + set header (4) + records */
  u8 pdu[IPFIX_MAX_PDU_BYTES];
  u32 n_pending = vec_len (im->pending);

  u32 rec_idx = 0;
  while (rec_idx < n_pending)
    {
      /* Start a new PDU */
      u32 pdu_records = 0;
      u8 *data_start = pdu + 16 + 4; /* after msg hdr + set hdr */
      u8 *p = data_start;

      while (rec_idx < n_pending)
	{
	  u32 remaining = (u32) (pdu + IPFIX_MAX_PDU_BYTES - p);
	  if (remaining < IPFIX_V4_DATA_RECORD_BYTES)
	    break; /* PDU full */

	  p += write_data_record_v4 (p, &im->pending[rec_idx]);
	  rec_idx++;
	  pdu_records++;
	  im->flows_exported++;
	}

      if (pdu_records == 0)
	break;

      u32 set_len = 4 + (u32) (p - data_start);
      u32 msg_len = 16 + set_len;

      /* Fill IPFIX message header */
      write_msg_header (pdu, (u16) msg_len, (u32) time (NULL), im->seq_no);
      im->seq_no += pdu_records;

      /* Fill data set header (set id = template id for data sets) */
      u8 *sh = pdu + 16;
      put_u16 (sh, IPFIX_TEMPLATE_ID_V4);      /* set id */
      put_u16 (sh + 2, (u16) set_len);          /* set length */

      send_to_collectors (im, pdu, msg_len);
    }

  /* Discard all pending records we just sent (or skipped). */
  vec_reset_length (im->pending);
}
