## Step 2 — Watch nDPI classify traffic

VPP is injecting synthetic TLS ClientHello packets for 12 applications every 30 seconds. Ask VPP what it has classified:

```
docker exec packetlens-vpp vppctl show ndpi applications
```{{exec}}

You'll see a table like this — packet and byte counters growing for each app:

```
Application          Packets    Bytes
YouTube              240        36480
Netflix              240        35520
GitHub               240        34560
Zoom                 240        35040
Spotify              240        34800
...
```

Check the raw Prometheus metrics the exporter is publishing:

```
docker exec packetlens-vpp wget -qO- http://packetlens-exporter:9197/metrics | grep vpp_ndpi_app_bytes
```{{exec}}

Each line is a labelled counter: `vpp_ndpi_app_bytes_total{app="YouTube"} 36480`

Check that Prometheus has scraped the target successfully:

```
docker exec packetlens-prometheus wget -qO- 'http://localhost:9090/api/v1/query?query=sum(vpp_ndpi_app_bytes_total)' | python3 -m json.tool
```{{exec}}

You should see a non-zero `value` in the result — the total bytes classified across all 12 applications.
