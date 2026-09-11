## You've completed the PacketLens demo!

### What you just ran

- **vpp-ndpi** classified 12 real application protocols (YouTube, Netflix, Zoom, Spotify, GitHub, TikTok, and more) using nDPI — directly inside VPP's forwarding path, with no mirror port and no external DPI box
- **vpp-exporter** published per-application packet, byte, and flow counters as Prometheus metrics
- **Grafana** visualised those counters on a live dashboard

### Overhead at a glance

| Mode | Latency added |
|------|--------------|
| Classifying (first 3–8 packets) | ~150 ns/pkt |
| Cached flow (bihash lookup) | ~8 ns/pkt |

### What PacketLens can do beyond classification

- **vpp-policy** — drop or permit traffic by application at wire speed
- **vpp-policer-ndpi** — token-bucket rate limiting per app (cap YouTube to 5 Mbps)
- **vpp-ddos** — per-IP PPS/BPS thresholds, inline scrubbing, SIP flood detection, SYN proxy
- **vpp-flowspec** — push BGP FlowSpec rules to upstream PE routers when thresholds fire
- **vpp-cdr** — export SIP CDRs to Homer SIPCapture via HEP3
- **vpp-ipfix** — RFC 7011 NetFlow/IPFIX enriched with nDPI metadata

### Next steps

- Website: [packetlens.dev](https://packetlens.dev)
- Get in touch: [contact@packetflow.dev](mailto:contact@packetflow.dev)
