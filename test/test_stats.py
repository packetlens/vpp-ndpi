"""Stats segment tests: verify vpp-ndpi registers and updates gauges in the
VPP stats segment (/ndpi/...) so that the Prometheus exporter can read them.

All tests share the session-scoped VPP instance started by conftest.py.
"""

import os
import struct
import time

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def connect_stats(vpp):
    """Return a connected VPPStats client.  Skip the test if stats socket
    is not available (e.g. VPP version predates statseg support)."""
    from vpp_papi.vpp_stats import VPPStats

    sock = vpp.stats_sock
    if not os.path.exists(sock):
        # Give VPP a moment to create the socket after startup
        for _ in range(30):
            if os.path.exists(sock):
                break
            time.sleep(0.2)

    if not os.path.exists(sock):
        pytest.skip(f"VPP stats socket not found at {sock}")

    stats = VPPStats(socketname=sock, timeout=5)
    stats.connect()
    return stats


def build_tls_hello_pkt(sni="www.youtube.com", sport=20001):
    """Build a minimal TLS ClientHello packet carrying the given SNI."""
    import struct as _struct
    from scapy.all import IP, TCP, Raw
    from scapy.all import raw as scapy_raw

    server_name = sni.encode("ascii")
    sn_entry = b"\x00" + _struct.pack("!H", len(server_name)) + server_name
    sn_list  = _struct.pack("!H", len(sn_entry)) + sn_entry
    sni_ext  = _struct.pack("!HH", 0x0000, len(sn_list)) + sn_list
    ext_block = _struct.pack("!H", len(sni_ext)) + sni_ext
    client_ver = b"\x03\x03"
    random_    = b"\x00" * 32
    sess_id    = b"\x00"
    cipher_sui = _struct.pack("!H", 2) + b"\xc0\x2f"
    comp_meth  = b"\x01\x00"
    ch_body    = client_ver + random_ + sess_id + cipher_sui + comp_meth + ext_block
    handshake  = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    record     = b"\x16\x03\x03" + _struct.pack("!H", len(handshake)) + handshake
    pkt = (
        IP(src="10.10.10.2", dst="10.10.10.100") /
        TCP(sport=sport, dport=443, flags="PA", seq=1) /
        Raw(record)
    )
    data = bytes(scapy_raw(pkt))
    return data.hex(), len(data)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStatsSegmentRegistration:
    """Verify that ndpi-stats-process registers all expected stat paths."""

    def test_stats_socket_exists(self, vpp):
        """Stats segment socket must exist after VPP starts."""
        sock = vpp.stats_sock
        # Allow up to 3 s for the process node to start
        for _ in range(30):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        assert os.path.exists(sock), f"stats socket not found: {sock}"

    def test_global_gauges_registered(self, vpp):
        """All seven global /ndpi/ gauges must be listed in the stats segment."""
        stats = connect_stats(vpp)
        try:
            # Give the stats-process node up to 3 s to push its first update
            for _ in range(30):
                names = stats.ls(["/ndpi/"])
                if "/ndpi/flows_created" in names:
                    break
                time.sleep(0.1)

            required = [
                "/ndpi/flows_created",
                "/ndpi/flows_classified",
                "/ndpi/flows_gave_up",
                "/ndpi/flows_active",
                "/ndpi/packets_scanned",
                "/ndpi/packets_cached",
                "/ndpi/ndpi_calls",
            ]
            for path in required:
                assert path in names, (
                    f"Expected stats path not found: {path}\n"
                    f"Available /ndpi/ entries: {names}"
                )
        finally:
            stats.disconnect()

    def test_per_app_gauges_registered(self, vpp):
        """At least a few well-known application gauge triplets must be present."""
        stats = connect_stats(vpp)
        try:
            # Wait for stats process node to register entries
            for _ in range(30):
                names = stats.ls(["/ndpi/app/"])
                if names:
                    break
                time.sleep(0.1)

            assert len(names) > 0, "No /ndpi/app/ entries found in stats segment"

            # Verify each entry comes in (bytes, packets, flows) triplets
            app_names = set()
            for n in names:
                parts = n.split("/")  # ['', 'ndpi', 'app', '<name>', '<metric>']
                if len(parts) == 5:
                    app_names.add(parts[3])

            # At least one triplet must be complete
            complete = 0
            for app in app_names:
                has_bytes   = f"/ndpi/app/{app}/bytes"   in names
                has_packets = f"/ndpi/app/{app}/packets" in names
                has_flows   = f"/ndpi/app/{app}/flows"   in names
                if has_bytes and has_packets and has_flows:
                    complete += 1

            assert complete > 0, (
                f"No complete (bytes+packets+flows) triplet found among: "
                f"{sorted(app_names)[:20]}"
            )
        finally:
            stats.disconnect()


class TestStatsSegmentValues:
    """Verify that stats values update correctly after traffic is processed."""

    def _setup_pg_and_traffic(self, vpp, stream_name="stats_test", sport=30001):
        """Create and run a TLS packet-generator stream on pg0."""
        rc, out, _ = vpp.vppctl("show interface")
        if "pg0" not in out:
            for cmd in [
                "create packet-generator interface pg0",
                "set interface state pg0 up",
                "set interface ip address pg0 10.10.10.1/24",
                "set interface ndpi pg0 enable",
            ]:
                rc, _, err = vpp.vppctl(cmd)
                assert rc == 0, f"{cmd}: {err}"

        hex_data, pkt_len = build_tls_hello_pkt(sni="www.youtube.com", sport=sport)
        cmd = (
            f"packet-generator new {{ name {stream_name} limit 6 "
            f"size {pkt_len}-{pkt_len} interface pg0 "
            f"node ip4-input data {{ hex 0x{hex_data} }} }}"
        )
        rc, _, err = vpp.vppctl(cmd)
        assert rc == 0, f"pg new failed: {err}"

        rc, _, err = vpp.vppctl("packet-generator enable")
        assert rc == 0, f"pg enable failed: {err}"
        time.sleep(1.0)

    def test_flows_created_increments(self, vpp):
        """flows_created gauge must be positive after injecting traffic."""
        stats = connect_stats(vpp)
        try:
            self._setup_pg_and_traffic(vpp, stream_name="stats_fc", sport=30010)

            # Allow stats process node to update (it runs every 1 s)
            value = 0
            for _ in range(15):
                try:
                    value = stats.get_counter("/ndpi/flows_created")
                    if value and value > 0:
                        break
                except Exception:
                    pass
                time.sleep(0.3)

            assert value is not None and value > 0, (
                f"flows_created expected > 0, got {value!r}"
            )
        finally:
            stats.disconnect()

    def test_packets_scanned_increments(self, vpp):
        """packets_scanned + packets_cached must be positive after traffic."""
        stats = connect_stats(vpp)
        try:
            self._setup_pg_and_traffic(vpp, stream_name="stats_ps", sport=30020)

            total = 0
            for _ in range(15):
                try:
                    scanned = stats.get_counter("/ndpi/packets_scanned") or 0
                    cached  = stats.get_counter("/ndpi/packets_cached")  or 0
                    total = scanned + cached
                    if total > 0:
                        break
                except Exception:
                    pass
                time.sleep(0.3)

            assert total > 0, f"packets_scanned + packets_cached expected > 0, got {total}"
        finally:
            stats.disconnect()

    def test_app_bytes_populated_after_classification(self, vpp):
        """At least one /ndpi/app/.../bytes gauge must be non-zero after
        injecting SNI-bearing traffic that nDPI can classify."""
        stats = connect_stats(vpp)
        try:
            self._setup_pg_and_traffic(vpp, stream_name="stats_ab", sport=30030)

            # nDPI classifies on SNI; wait for classification + stats update
            app_names = []
            for _ in range(20):
                names = stats.ls(["/ndpi/app/"])
                for n in names:
                    if n.endswith("/bytes"):
                        try:
                            v = stats.get_counter(n)
                            if v and v > 0:
                                app_names.append((n, v))
                        except Exception:
                            pass
                if app_names:
                    break
                time.sleep(0.5)

            assert len(app_names) > 0, (
                "No /ndpi/app/.../bytes gauge has a non-zero value after "
                "injecting SNI traffic. This likely means the stats process "
                "node is not updating per-app gauges correctly."
            )
        finally:
            stats.disconnect()
