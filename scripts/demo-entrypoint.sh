#!/usr/bin/env bash
# Demo entrypoint: starts VPP with vpp-ndpi, injects synthetic TLS traffic
# in a loop so the Grafana dashboard always shows live classification data.
set -euo pipefail

SRC_DIR="${SRC_DIR:-/src}"
CLI_SOCK=/run/vpp/cli.sock

mkdir -p /run/vpp /var/log/vpp

cat > /tmp/demo.conf <<EOF
unix {
    nodaemon
    log /var/log/vpp/vpp.log
    cli-listen ${CLI_SOCK}
}
api-segment { prefix vpe }
socksvr { socket-name /run/vpp/api.sock }
statseg {
    socket-name /run/vpp/stats.sock
    size 32m
    per-node-counters on
}
plugins {
    path ${SRC_DIR}/build/lib/vpp_plugins:/usr/lib/x86_64-linux-gnu/vpp_plugins
    plugin default { disable }
    plugin ndpi_plugin.so { enable }
}
ndpi { flows-per-worker 16384 }
EOF

echo "[demo] Starting VPP..."
vpp -c /tmp/demo.conf &
VPP_PID=$!

for i in $(seq 1 60); do
    [ -S "${CLI_SOCK}" ] && break
    sleep 0.2
done
[ -S "${CLI_SOCK}" ] || { echo "[demo] ERROR: VPP failed to start"; cat /var/log/vpp/vpp.log; exit 1; }

echo "[demo] VPP ready"
vppctl -s "${CLI_SOCK}" show ndpi version

echo "[demo] Setting up pg0 interface"
vppctl -s "${CLI_SOCK}" create packet-generator interface pg0
vppctl -s "${CLI_SOCK}" set interface state pg0 up
vppctl -s "${CLI_SOCK}" set interface ip address pg0 10.10.10.1/24
vppctl -s "${CLI_SOCK}" set interface ndpi pg0 enable

inject_traffic() {
    python3 << 'PYEOF'
import struct, subprocess, sys
from scapy.all import IP, TCP, Raw, raw

CLI = "/run/vpp/cli.sock"

def vppctl(cmd):
    r = subprocess.run(["vppctl", "-s", CLI] + cmd.split(), capture_output=True)
    return r.returncode == 0

def build_tls_client_hello(sni):
    server_name = sni.encode("ascii")
    sn_entry = b"\x00" + struct.pack("!H", len(server_name)) + server_name
    sn_list  = struct.pack("!H", len(sn_entry)) + sn_entry
    sni_ext  = struct.pack("!HH", 0x0000, len(sn_list)) + sn_list
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext
    ch_body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
               struct.pack("!H", 2) + b"\xc0\x2f" + b"\x01\x00" + ext_block)
    handshake = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake

APPS = [
    ("youtube",   "www.youtube.com",    10001),
    ("google",    "www.google.com",     10002),
    ("github",    "github.com",         10003),
    ("netflix",   "www.netflix.com",    10004),
    ("facebook",  "www.facebook.com",   10005),
    ("twitter",   "twitter.com",        10006),
    ("whatsapp",  "www.whatsapp.com",   10007),
    ("instagram", "www.instagram.com",  10008),
    ("zoom",      "zoom.us",            10009),
    ("spotify",   "open.spotify.com",   10010),
    ("tiktok",    "www.tiktok.com",     10011),
    ("amazon",    "www.amazon.com",     10012),
]

for name, _, _ in APPS:
    vppctl(f"packet-generator delete {name}")

for name, sni, sport in APPS:
    tls = build_tls_client_hello(sni)
    pkt = IP(src="10.10.10.2", dst="10.10.10.100") / TCP(sport=sport, dport=443, flags="PA", seq=1) / Raw(tls)
    data = raw(pkt)
    cmd = (f"packet-generator new {{ name {name} limit 20 "
           f"size {len(data)}-{len(data)} interface pg0 node ip4-input "
           f"data {{ hex 0x{data.hex()} }} }}")
    vppctl(cmd)

vppctl("packet-generator enable")
print(f"[demo] Injected {len(APPS)} app streams", flush=True)
PYEOF
}

echo "[demo] Injecting initial traffic..."
inject_traffic

echo "[demo] Ready — Grafana at http://localhost:3000"
echo "[demo] Run: vppctl -s /run/vpp/cli.sock show ndpi applications"

# Re-inject every 30 s so counters stay live
while kill -0 "${VPP_PID}" 2>/dev/null; do
    sleep 30
    inject_traffic || true
done

echo "[demo] VPP exited"
