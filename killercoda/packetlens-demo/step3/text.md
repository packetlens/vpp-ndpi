## Step 3 — Grafana dashboard

Grafana is running on port 3000. Killercoda exposes it as a tab — click the **Traffic** tab above the terminal, or use the link below:

{{TRAFFIC_HOST1_3000}}

The dashboard loads automatically with **no login required**.

You'll see:
- **Top Applications** bar chart — YouTube, Netflix, GitHub, Zoom, Spotify, TikTok and more
- **Bytes/sec per app** time-series graph — counters updating every 15 seconds as VPP re-injects traffic
- **Engine stats** — flows active, classification rate, memory usage

### CLI deep-dive (optional)

Show the nDPI plugin version and build info:

```
docker exec packetlens-vpp vppctl show ndpi version
```{{exec}}

Show the flow table (up to 10 entries):

```
docker exec packetlens-vpp vppctl show ndpi flows
```{{exec}}

Show per-interface statistics:

```
docker exec packetlens-vpp vppctl show ndpi interfaces
```{{exec}}

> The synthetic traffic re-injects every 30 seconds, so counters keep growing even when you're just watching.
