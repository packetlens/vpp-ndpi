/**
 * ndpi_classify_callback.h — PacketLens DPI classification callback API
 *
 * External plugins (AI/ML detectors, analytics engines, custom enforcement
 * logic) register a callback with vpp-ndpi.  After nDPI reaches a final
 * verdict on a flow, PacketLens calls the function once with the complete
 * L7 classification result — application name ID, category, nDPI risk
 * bitmask, TLS SNI, and JA3 fingerprint.
 *
 * Combined with ddos_ai_callback.h, this gives an AI/ML detector the full
 * pipeline:
 *
 *   vpp-ndpi classifies → ndpi callback fires with L7 verdict
 *      ↓
 *   Detector scores the flow (e.g. Link11 4D: What/Who/When/Where)
 *      ↓
 *   ddos-ai-classify drops/rate-limits source IPs with score >= threshold
 *      ↓
 *   Enforcement latency: under 1 ms, no BGP, no external process
 *
 * Usage
 * -----
 *   1. Implement ndpi_on_flow_classified_fn_t in your plugin.
 *   2. Call ndpi_register_classify_callback() from your plugin init.
 *   3. Call ndpi_unregister_classify_callback() on plugin unload.
 *
 * Thread safety
 * -------------
 *   The callback is invoked from VPP worker threads in the packet-processing
 *   hot path.  It MUST be:
 *     - Re-entrant: called simultaneously from multiple workers.
 *     - Non-blocking: no mutex, no I/O, no syscall.
 *     - Alloc-free: no heap allocation.
 *     - VPP-API-free: do not call any vlib/vnet function.
 *
 * Copyright (c) 2026 PacketFlow (packetflow.dev)
 * Licensed under Apache 2.0
 */

#ifndef __ndpi_classify_callback_h__
#define __ndpi_classify_callback_h__

#include <vppinfra/types.h>

/**
 * Flow classification callback.
 *
 * Called once per flow, on the packet that triggers the final nDPI verdict
 * (either a confident classify or a give-up after max_pkts / timeout).
 *
 * @param src_ip4        Source IPv4 address (host byte order); 0 for IPv6
 * @param dst_ip4        Destination IPv4 address (host byte order); 0 for IPv6
 * @param proto          IP protocol (6=TCP, 17=UDP, 1=ICMP, …)
 * @param sport          Source port (host byte order; 0 for non-TCP/UDP)
 * @param dport          Destination port (host byte order; 0 for non-TCP/UDP)
 * @param master_protocol  nDPI master protocol ID (e.g. TLS=91, HTTP=7)
 * @param app_protocol   nDPI application protocol ID (e.g. YouTube=254)
 * @param category       nDPI category ID (e.g. Media=4, VPN=13)
 * @param risk           nDPI risk bitmask (bit 0=known proto, bit N=risk N)
 * @param sni            TLS/QUIC SNI hostname — NUL-terminated, may be empty
 * @param ja3            JA3 client fingerprint — 32-char hex, may be empty
 * @param sw_if_index    VPP interface index where the flow arrived
 * @param ctx            Opaque pointer supplied at registration
 *
 * Note: sni and ja3 point into the flow entry and are valid only for the
 * duration of this call.  Copy them if you need to retain them.
 */
typedef void (*ndpi_on_flow_classified_fn_t)(
    u32 src_ip4, u32 dst_ip4,
    u8 proto, u16 sport, u16 dport,
    u16 master_protocol, u16 app_protocol, u16 category,
    u64 risk,
    const u8 *sni, const u8 *ja3,
    u32 sw_if_index,
    void *ctx);

/**
 * Register a flow-classification callback with vpp-ndpi.
 *
 * At most one callback is active at a time.  Calling this function replaces
 * any previously registered callback.  The swap is protected by the VPP
 * worker barrier — no worker will call the old function after this returns.
 *
 * @param name  Human-readable identifier shown in 'show ndpi callback' (max 63 chars)
 * @param fn    Classification callback (must satisfy thread-safety requirements)
 * @param ctx   Opaque context; passed verbatim to fn on every invocation
 * @return 0 on success, non-zero on error
 */
int ndpi_register_classify_callback (const char *name,
                                      ndpi_on_flow_classified_fn_t fn,
                                      void *ctx);

/**
 * Unregister the currently registered classification callback.
 * Safe to call with no callback registered.
 */
void ndpi_unregister_classify_callback (void);

#endif /* __ndpi_classify_callback_h__ */
