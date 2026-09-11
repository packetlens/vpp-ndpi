/*
 * cdr_hep3.c
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * cdr_hep3.c - HEP v3 frame builder.
 *
 * HEP (Homer Encapsulation Protocol) v3 frame layout:
 *
 *   Bytes  0-3:  magic "HEP3"
 *   Bytes  4-5:  total frame length (big-endian u16, includes these 6 bytes)
 *   Bytes  6+:   TLV chunks:
 *                  vendor_id (u16 BE) | type_id (u16 BE) | length (u16 BE) | data
 *                  length includes the 6-byte chunk header itself.
 *
 * Standard chunk types (vendor 0x0000):
 *   0x0001  IP family     (1 byte)  — 2 = IPv4
 *   0x0002  IP protocol   (1 byte)  — 6 = TCP, 17 = UDP
 *   0x0003  IPv4 src addr (4 bytes, network order)
 *   0x0004  IPv4 dst addr (4 bytes, network order)
 *   0x0007  src port      (2 bytes, network order)
 *   0x0008  dst port      (2 bytes, network order)
 *   0x0009  timestamp sec (4 bytes)
 *   0x000a  timestamp µs  (4 bytes)
 *   0x000b  proto type    (1 byte)  — 1 = SIP, 5 = RTCP
 *   0x000c  agent ID      (4 bytes)
 *   0x000e  auth key      (variable string)
 *   0x000f  payload       (raw SIP message)
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#include <cdr/cdr.h>
#include <vlib/vlib.h>

/* ── Chunk writers ───────────────────────────────────────────────────────── */

/* Each writer advances *pp by the bytes consumed.
 * Returns 0 on success, -1 if buf_end would be exceeded. */

#define CDR_CHECK(p, end, n) \
  do { if ((p) + (n) > (end)) return -1; } while (0)

static int
chunk_u8 (u8 **pp, u8 *end, u16 type, u8 val)
{
  CDR_CHECK (*pp, end, 7);
  u8 *p = *pp;
  p[0] = 0; p[1] = 0;           /* vendor = 0x0000 */
  p[2] = type >> 8; p[3] = type & 0xff;
  p[4] = 0; p[5] = 7;           /* length = 7 */
  p[6] = val;
  *pp += 7;
  return 0;
}

static int
chunk_u16 (u8 **pp, u8 *end, u16 type, u16 val_net)
{
  CDR_CHECK (*pp, end, 8);
  u8 *p = *pp;
  p[0] = 0; p[1] = 0;
  p[2] = type >> 8; p[3] = type & 0xff;
  p[4] = 0; p[5] = 8;           /* length = 8 */
  clib_memcpy (p + 6, &val_net, 2);   /* val_net already in network order */
  *pp += 8;
  return 0;
}

static int
chunk_u32 (u8 **pp, u8 *end, u16 type, u32 val)
{
  CDR_CHECK (*pp, end, 10);
  u8 *p = *pp;
  p[0] = 0; p[1] = 0;
  p[2] = type >> 8; p[3] = type & 0xff;
  p[4] = 0; p[5] = 10;          /* length = 10 */
  p[6] = val >> 24; p[7] = (val >> 16) & 0xff;
  p[8] = (val >> 8) & 0xff; p[9] = val & 0xff;
  *pp += 10;
  return 0;
}

/* ip4 address is already in network order — write bytes directly */
static int
chunk_ip4 (u8 **pp, u8 *end, u16 type, u32 addr_net)
{
  CDR_CHECK (*pp, end, 10);
  u8 *p = *pp;
  p[0] = 0; p[1] = 0;
  p[2] = type >> 8; p[3] = type & 0xff;
  p[4] = 0; p[5] = 10;
  clib_memcpy (p + 6, &addr_net, 4);
  *pp += 10;
  return 0;
}

static int
chunk_bytes (u8 **pp, u8 *end, u16 type, const u8 *data, u16 len)
{
  u16 chunk_len = 6 + len;
  CDR_CHECK (*pp, end, chunk_len);
  u8 *p = *pp;
  p[0] = 0; p[1] = 0;
  p[2] = type >> 8; p[3] = type & 0xff;
  p[4] = chunk_len >> 8; p[5] = chunk_len & 0xff;
  if (len)
    clib_memcpy (p + 6, data, len);
  *pp += chunk_len;
  return 0;
}

/* ── Public builder ──────────────────────────────────────────────────────── */

int
cdr_build_hep3 (u8 *out, int out_max,
                u32 src_ip4_net, u32 dst_ip4_net,
                u16 src_port_net, u16 dst_port_net,
                u8  ip_proto,
                u32 ts_sec, u32 ts_usec,
                u32 agent_id,
                const u8 *password, u16 password_len,
                const u8 *payload, u16 payload_len)
{
  if (out_max < 6)
    return -1;

  u8 *start = out;
  u8 *end   = out + out_max;

  /* 6-byte frame header — we'll fill in total_len at the end */
  out[0] = 'H'; out[1] = 'E'; out[2] = 'P'; out[3] = '3';
  out[4] = 0;   out[5] = 0;   /* placeholder for total length */
  u8 *p = out + 6;

#define W(fn, ...) do { if (fn(__VA_ARGS__) < 0) return -1; } while(0)

  W (chunk_u8,  &p, end, 0x0001, 2);                     /* IP family = IPv4 */
  W (chunk_u8,  &p, end, 0x0002, ip_proto);               /* IP proto */
  W (chunk_ip4, &p, end, 0x0003, src_ip4_net);            /* src IP */
  W (chunk_ip4, &p, end, 0x0004, dst_ip4_net);            /* dst IP */
  W (chunk_u16, &p, end, 0x0007, src_port_net);           /* src port */
  W (chunk_u16, &p, end, 0x0008, dst_port_net);           /* dst port */
  W (chunk_u32, &p, end, 0x0009, ts_sec);                 /* timestamp sec */
  W (chunk_u32, &p, end, 0x000a, ts_usec);                /* timestamp µs */
  W (chunk_u8,  &p, end, 0x000b, 1);                      /* proto type = SIP */
  W (chunk_u32, &p, end, 0x000c, agent_id);               /* capture agent */
  if (password && password_len)
    W (chunk_bytes, &p, end, 0x000e, password, password_len); /* auth key */
  W (chunk_bytes, &p, end, 0x000f, payload, payload_len); /* SIP payload */

#undef W

  u16 total = (u16)(p - start);
  start[4] = total >> 8;
  start[5] = total & 0xff;
  return (int) total;
}
