## PacketLens — DPI inside VPP

**PacketLens** is an open-source plugin suite that runs [ntop nDPI](https://github.com/ntop/nDPI) directly inside [FD.io VPP](https://fd.io) — a 100G–800G packet processor used by ISPs, telcos, and CDN operators.

Instead of a $200K DPI appliance on a mirror port, PacketLens classifies every flow in the forwarding path — in nanoseconds, on the same CPU core as your router.

### What you'll do in this scenario

1. Start the PacketLens demo stack with a single Docker Compose command
2. Watch VPP classify YouTube, Netflix, Zoom, Spotify, and 8 other applications in real time
3. Explore the live Grafana dashboard showing per-application traffic counters

### What's running

```
┌─────────────────────────────────────────────────────┐
│  VPP + vpp-ndpi                                     │
│  (classifies synthetic TLS traffic every 30 s)      │
│           │                                         │
│           ▼ stats socket                            │
│  vpp-exporter  ──► Prometheus  ──► Grafana :3000    │
└─────────────────────────────────────────────────────┘
```

> **Note:** The demo image is being pulled in the background. It will be ready by the time you reach Step 1.

Click **START SCENARIO** to begin.
