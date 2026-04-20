"""Integration tests: push traffic through VPP's packet generator with
scapy-built packets and verify vpp-ndpi classifies/counts them.

Tests share a single session-scoped VPP instance. To avoid a VPP bug with
repeated `packet-generator new/delete` cycles, this file runs a single
comprehensive test that creates multiple streams upfront and verifies
classification results afterward.
"""

import re
import time


def build_pkt_hex(src="10.10.10.2", dst="10.10.10.100", proto="udp",
                  sport=12345, dport=53, payload_size=32):
    """Build a valid IPv4 packet with scapy. Return (hex_str, length)."""
    from scapy.all import IP, UDP, TCP, Raw
    from scapy.all import raw as scapy_raw

    ip = IP(src=src, dst=dst, ttl=64)
    if proto == "udp":
        pkt = ip / UDP(sport=sport, dport=dport) / Raw(b"\x00" * payload_size)
    else:
        pkt = ip / TCP(sport=sport, dport=dport, flags="S") / Raw(
            b"\x00" * max(payload_size - 12, 0)
        )
    b = bytes(scapy_raw(pkt))
    return b.hex(), len(b)


def setup_pg(vpp, name="pg0", addr="10.10.10.1/24"):
    rc, out, err = vpp.vppctl("show interface")
    if name in out:
        return
    for cmd in [
        f"create packet-generator interface {name}",
        f"set interface state {name} up",
        f"set interface ip address {name} {addr}",
        f"set interface ndpi {name} enable",
    ]:
        rc, out, err = vpp.vppctl(cmd)
        assert rc == 0, f"{cmd} failed: rc={rc} out={out} err={err}"


def create_stream(vpp, stream, iface="pg0", count=5,
                  sport=12345, dport=53, dst="10.10.10.100"):
    hex_data, pkt_len = build_pkt_hex(dst=dst, sport=sport, dport=dport)
    cmd = (
        f"packet-generator new {{ name {stream} limit {count} "
        f"size {pkt_len}-{pkt_len} interface {iface} "
        f"node ip4-input data {{ hex 0x{hex_data} }} }}"
    )
    rc, out, err = vpp.vppctl(cmd)
    assert rc == 0, f"pg new {stream} failed: {out} {err}"


def _int_after(out, label):
    m = re.search(rf"{label}:\s*(\d+)", out)
    return int(m.group(1)) if m else None


def test_full_pg_flow(vpp):
    """One comprehensive test that validates end-to-end: pg setup, multiple
    streams, flow creation, packet counting, and CLI reporting."""
    setup_pg(vpp)

    # Create several distinct flows (different src port => different 5-tuple)
    streams = [
        ("flow1", 10001, 53),   # UDP/53 like DNS
        ("flow2", 10002, 80),   # UDP-on-port-80
        ("flow3", 10003, 443),
        ("flow4", 10004, 1234),
        ("flow5", 10005, 5000),
    ]
    for name, sport, dport in streams:
        create_stream(vpp, name, count=4, sport=sport, dport=dport)

    # Run all of them at once
    rc, out, err = vpp.vppctl("packet-generator enable")
    assert rc == 0, f"pg enable failed: {out} {err}"

    # Wait for all packets to drain
    time.sleep(1.0)

    # Now gather results
    rc, out, err = vpp.vppctl("show ndpi stats")
    assert rc == 0, err
    flows = _int_after(out, "flows created") or 0
    scanned = _int_after(out, "packets scanned") or 0
    cached = _int_after(out, "packets cached") or 0

    assert flows >= len(streams), (
        f"expected >={len(streams)} flows, got {flows}\n{out}"
    )
    assert scanned + cached >= len(streams) * 4, (
        f"expected >={len(streams) * 4} packets, got scanned={scanned} "
        f"cached={cached}\n{out}"
    )

    # Verify flows are visible in `show ndpi flows`
    rc, out, err = vpp.vppctl("show ndpi flows count 50")
    assert rc == 0, err
    assert "10.10.10.2" in out, f"flow source not visible:\n{out}"

    # Verify the top of `show ndpi applications` responds
    rc, out, err = vpp.vppctl("show ndpi applications")
    assert rc == 0, err
    # Header must be present even if nothing classified fully
    assert "Application" in out or "no classified" in out


# ── Phase 7: DPI classification callback tests ────────────────────────────────

def test_ndpi_callback_default_state(vpp):
    """show ndpi callback reports 'none registered' by default."""
    rc, out, err = vpp.vppctl("show ndpi callback")
    assert rc == 0, f"show ndpi callback failed: {err}"
    assert "none registered" in out, (
        f"expected 'none registered' in default state:\n{out}"
    )
    assert "calls:" in out, f"call counter line missing:\n{out}"


def test_ndpi_callback_calls_counter_present(vpp):
    """show ndpi callback always emits a 'calls:' counter line."""
    rc, out, err = vpp.vppctl("show ndpi callback")
    assert rc == 0, err
    m = re.search(r"calls:\s*(\d+)", out)
    assert m is not None, f"calls counter not found in:\n{out}"
    # No callback registered — calls must be 0
    assert int(m.group(1)) == 0, (
        f"expected calls=0 with no callback registered, got {m.group(1)}"
    )
