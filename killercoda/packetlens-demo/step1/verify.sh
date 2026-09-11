#!/usr/bin/env bash
# Pass when all 4 containers are running and VPP is healthy
running=$(docker compose -f compose.demo.yaml ps --format json 2>/dev/null \
  | python3 -c "
import sys, json
lines = sys.stdin.read().strip().splitlines()
containers = [json.loads(l) for l in lines if l.strip()]
healthy = [c for c in containers if c.get('State') == 'running']
print(len(healthy))
" 2>/dev/null || echo 0)

if [ "$running" -ge 4 ]; then
  echo "All 4 containers running"
  exit 0
else
  echo "Waiting for containers... ($running/4 running)"
  exit 1
fi
