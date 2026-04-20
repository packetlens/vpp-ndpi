# vpp-ndpi

**Deep Packet Inspection inside FD.io VPP** — classify 300+ applications (YouTube, Zoom, Netflix, SIP, TLS, QUIC, BitTorrent, GTP-U, and more) directly in the data-plane forwarding path using [ntop/nDPI](https://github.com/ntop/nDPI).

- **No mirror port.** No external DPI box. Classification runs as a VPP feature arc node on `ip4-unicast` / `ip6-unicast`.
- **< 8 ns overhead** per cached packet (bihash lookup + opaque write).
- **100G–800G line rate** — VPP multi-worker, scales linearly.
- **Apache 2.0** — free to use, evaluate, and build on.

Part of the [PacketLens](https://packetlens.dev) plugin suite by [PacketFlow](https://packetflow.dev).

---

## Quick demo

```
$ docker compose -f compose.demo.yaml up
```

Opens Grafana at **http://localhost:3001** showing live per-application traffic counters for 12 injected TLS flows (YouTube, Netflix, GitHub, Zoom, Spotify, TikTok, Amazon, …).

Or run it in your browser via Killercoda — no install required:  
**https://killercoda.com/packetlens/course/packetlens-demo**

---

## What it does

```
vpp# show ndpi applications
Application                   Flows    Packets          Bytes        %
YouTube                           1         20           2320     8.4%
NetFlix                           1         20           2320     8.4%
Github                            1         20           2220     8.1%
Zoom                              1         20           2300     8.4%
Spotify                           1         20           2340     8.5%
...

vpp# show ndpi flows
Src IP          Dst IP          Proto SPort DPort App         SNI                     Bytes
10.10.10.2      10.10.10.100    6     10001 443   YouTube     www.youtube.com           580
10.10.10.2      10.10.10.100    6     10009 443   Zoom        zoom.us                   580
```

---

## Build & test

### Prerequisites

- Docker (for the easiest path)
- Or: VPP 25.10+ + libndpi-dev + CMake 3.16+

### One-command demo (Docker Compose)

```bash
docker compose -f compose.demo.yaml up
# Grafana → http://localhost:3001  (no login)
```

### Build from source

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Run tests

```bash
pytest test/test_ndpi.py test/test_smoke.py test/test_stats.py -v
```

---

## Architecture

vpp-ndpi registers as a node on the `ip4-unicast` and `ip6-unicast` feature arcs. It writes classification results into the VPP buffer opaque area — a 12-byte struct read by downstream plugins in the same arc pass:

```c
typedef struct {
  u16  app_protocol;  /* nDPI app ID (e.g., 114 = YouTube, 225 = SIP) */
  u8   category;      /* nDPI category (e.g., 5 = VideoStreaming)      */
  u32  risk;          /* nDPI risk bitmask (Tor, malware C2, etc.)     */
  u8   classified;    /* 0=classifying, 1=cached, 2=gave_up            */
  u8   _pad[4];
} ndpi_buffer_opaque_t;
```

**Per-worker flow table:** bihash_16_8 (IPv4) / bihash_48_8 (IPv6) — no cross-worker contention.  
**Classification:** first 3–8 packets per flow are submitted to nDPI; once classified the result is cached for the remainder of the flow lifetime.

---

## Performance

| Metric | Value | Notes |
|--------|-------|-------|
| Overhead (classifying) | ~150 ns/pkt | First 3–8 pkts per flow |
| Overhead (cached) | ~8 ns/pkt | bihash lookup only |
| Protocols classified | 300+ | nDPI 4.2.0 |
| Max flows per worker | 1M | configurable |
| Classification convergence | 3–8 pkts | 95th pct, TCP/TLS |

---

## Plugin stack (PacketLens)

vpp-ndpi is the classification foundation for the full PacketLens suite:

```
vpp-ndpi (this repo)          ← classify: app, category, SNI, JA3, risk
  ↓
vpp-policy                    ← enforce: drop / permit by app class
vpp-policer-ndpi              ← rate-limit: per-app token-bucket
  ↓
vpp-ddos                      ← detect: per-IP PPS/BPS thresholds, SYN proxy, VoIP flood
vpp-flowspec                  ← react: BGP FlowSpec push to upstream PE
vpp-cdr                       ← mirror: SIP CDR export via HEP3 to Homer
vpp-ipfix                     ← export: RFC 7011 IPFIX enriched with nDPI metadata
```

Commercial plugins and support available from [PacketFlow](https://packetflow.dev).

---

## Repository layout

```
vpp-ndpi/
├── CMakeLists.txt
├── src/plugins/ndpi/       Core DPI classification plugin (C)
├── exporter/               Prometheus metrics exporter (Go)
├── test/                   pytest integration tests
├── scripts/                Demo entrypoint
├── labs/                   Grafana + Prometheus configs
├── compose.demo.yaml       One-command demo stack
├── Dockerfile.ci           CI build image
├── Dockerfile.demo         Demo image (VPP + plugin + synthetic traffic)
├── .devcontainer/          GitHub Codespaces config
└── killercoda/             Browser-based interactive demo scenario
```

---

## License

Apache 2.0. Dynamically links libndpi (LGPL-3.0-or-later).
