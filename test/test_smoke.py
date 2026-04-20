"""Smoke tests: plugin builds, loads, and core CLI commands respond."""

import os

from conftest import find_plugin_so


def test_plugin_file_exists():
    p = find_plugin_so()
    assert p is not None, "ndpi_plugin.so not found after build"
    assert os.path.getsize(p) > 0, "plugin .so is empty"


def test_vpp_starts_with_plugin(vpp):
    rc, out, err = vpp.vppctl("show plugins")
    assert rc == 0, f"vppctl failed: {err}"
    assert "ndpi_plugin.so" in out, f"plugin not listed:\n{out}"


def test_show_ndpi_version(vpp):
    rc, out, err = vpp.vppctl("show ndpi version")
    assert rc == 0, f"vppctl failed: {err}"
    assert "vpp-ndpi plugin" in out
    assert "libndpi" in out


def test_show_ndpi_stats_initial(vpp):
    rc, out, err = vpp.vppctl("show ndpi stats")
    assert rc == 0, f"vppctl failed: {err}"
    assert "flows created" in out.lower() or "flows_created" in out.lower()


def test_show_ndpi_applications_empty(vpp):
    rc, out, err = vpp.vppctl("show ndpi applications")
    assert rc == 0, f"vppctl failed: {err}"
    # No traffic yet -> either empty or header only
    assert "Application" in out or "no classified" in out


def test_show_ndpi_flows_empty(vpp):
    rc, out, err = vpp.vppctl("show ndpi flows")
    assert rc == 0, f"vppctl failed: {err}"
    assert "Src IP" in out or "(no flows)" in out
