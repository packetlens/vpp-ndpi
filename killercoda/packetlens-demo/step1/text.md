## Step 1 — Start the demo stack

Download the Compose file and start all four services with one command:

```
curl -fsSL https://raw.githubusercontent.com/garyachy/vpp-ndpi/main/compose.demo.yaml -o compose.demo.yaml
docker compose -f compose.demo.yaml up -d
```{{exec}}

This starts:
- **VPP** with vpp-ndpi loaded — classifies synthetic TLS traffic for 12 apps
- **vpp-exporter** — scrapes VPP's stats segment and exposes Prometheus metrics
- **Prometheus** — stores the metrics
- **Grafana** — visualises per-application byte and packet counters

Wait for VPP to become healthy (the exporter won't start until VPP's CLI socket is ready):

```
docker compose -f compose.demo.yaml ps
```{{exec}}

You should see `packetlens-vpp` show `healthy` and all four containers as `running`.

> VPP needs ~10 seconds to initialise. Re-run `ps` if the exporter isn't up yet.
