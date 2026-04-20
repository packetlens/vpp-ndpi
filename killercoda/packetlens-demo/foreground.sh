#!/usr/bin/env bash
# Killercoda foreground setup — runs on VM boot while user reads the intro.
set -euo pipefail

echo ">>> Pulling PacketLens demo images..."
docker pull ghcr.io/packetlens/vpp-ndpi:latest
docker pull ghcr.io/packetlens/vpp-ndpi-exporter:latest &
docker pull prom/prometheus:v2.51.2 &
docker pull grafana/grafana:10.4.2 &
wait
echo ">>> All images pulled"

# Extract labs configs bundled inside the demo image (at /src/labs/)
echo ">>> Extracting Prometheus + Grafana configs from demo image..."
mkdir -p /root/labs
docker create --name extract-tmp ghcr.io/packetlens/vpp-ndpi:latest sh
docker cp extract-tmp:/src/labs/. /root/labs/
docker rm extract-tmp

# Write the Compose file using pre-built images
cat > /root/compose.demo.yaml << 'COMPOSE'
services:
  vpp:
    image: ghcr.io/packetlens/vpp-ndpi:latest
    container_name: packetlens-vpp
    privileged: true
    volumes:
      - vpp-run:/run/vpp
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "test", "-S", "/run/vpp/cli.sock"]
      interval: 5s
      timeout: 3s
      retries: 20
      start_period: 15s

  vpp-exporter:
    image: ghcr.io/packetlens/vpp-ndpi-exporter:latest
    container_name: packetlens-exporter
    command: ["--stats-socket=/run/vpp/stats.sock", "--listen=:9197"]
    volumes:
      - vpp-run:/run/vpp:ro
    depends_on:
      vpp:
        condition: service_healthy
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:v2.51.2
    container_name: packetlens-prometheus
    volumes:
      - ./labs/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    depends_on:
      - vpp-exporter
    restart: unless-stopped

  grafana:
    image: grafana/grafana:10.4.2
    container_name: packetlens-grafana
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_AUTH_DISABLE_LOGIN_FORM=true
      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/flowlens-ndpi.json
    volumes:
      - ./labs/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./labs/grafana/dashboards:/var/lib/grafana/dashboards:ro
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    restart: unless-stopped

volumes:
  vpp-run:
COMPOSE

echo ">>> Setup complete — scenario ready"
