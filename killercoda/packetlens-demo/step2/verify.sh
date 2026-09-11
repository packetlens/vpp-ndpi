#!/usr/bin/env bash
# Pass when Prometheus has a non-zero byte total
total=$(docker exec packetlens-prometheus wget -qO- \
  'http://localhost:9090/api/v1/query?query=sum(vpp_ndpi_app_bytes_total)' 2>/dev/null \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
results = d.get('data', {}).get('result', [])
if results:
    print(int(float(results[0]['value'][1])))
else:
    print(0)
" 2>/dev/null || echo 0)

if [ "$total" -gt 0 ]; then
  echo "Prometheus has $total bytes classified — nDPI is working"
  exit 0
else
  echo "No data yet — wait a few seconds and try again"
  exit 1
fi
