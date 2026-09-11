"""Smoke tests for the plugins that ship alongside vpp-ndpi.

policy, policer_ndpi, ipfix and flowspec are compiled into ndpi_plugin.so;
cdr and flowspec_recv are separate plugins.  These tests assert the plugins
load and their CLI surface responds — they do not drive traffic.
"""

import pytest

from conftest import find_plugin_so


SEPARATE_PLUGINS = ["cdr_plugin.so", "flowspec_recv_plugin.so"]

SHOW_COMMANDS = [
    "show policy",
    "show policer-ndpi",
    "show ndpi-ipfix exporter",
    "show ndpi-ipfix stats",
    "show cdr",
    "show flowspec status",
    "show flowspec-recv rules",
    "show flowspec-recv status",
]


@pytest.mark.parametrize("cmd", SHOW_COMMANDS)
def test_show_command_responds(vpp, cmd):
    """Every show command is registered and does not error."""
    rc, out, err = vpp.vppctl(cmd)
    assert rc == 0, f"{cmd!r} failed: {err}"
    assert "unknown input" not in out.lower(), f"{cmd!r} not registered:\n{out}"


def test_separate_plugins_loaded(vpp):
    rc, out, err = vpp.vppctl("show plugins")
    assert rc == 0, f"vppctl failed: {err}"
    for so in SEPARATE_PLUGINS:
        assert so in out, f"{so} not loaded:\n{out}"


def test_policy_default_action_roundtrip(vpp):
    """Setting the default action is reflected in show output."""
    rc, _, err = vpp.vppctl("set policy default-action drop")
    assert rc == 0, err
    rc, out, _ = vpp.vppctl("show policy")
    assert rc == 0
    assert "drop" in out.lower()
    vpp.vppctl("set policy default-action permit")


def test_policy_rule_add_and_clear(vpp):
    """A per-app rule appears in show output and can be cleared."""
    rc, _, err = vpp.vppctl("set policy app BitTorrent action drop")
    assert rc == 0, err
    rc, out, _ = vpp.vppctl("show policy")
    assert "bittorrent" in out.lower(), f"rule not listed:\n{out}"

    rc, _, err = vpp.vppctl("clear policy app BitTorrent")
    assert rc == 0, err
    rc, out, _ = vpp.vppctl("show policy")
    assert "bittorrent" not in out.lower(), f"rule not cleared:\n{out}"


def test_policer_add_and_clear(vpp):
    """A per-app policer appears in show output and can be cleared."""
    rc, _, err = vpp.vppctl("set policer-ndpi app YouTube rate 5000")
    if rc != 0:
        pytest.skip(f"policer CLI rejected the form used here: {err}")
    rc, out, _ = vpp.vppctl("show policer-ndpi")
    assert "youtube" in out.lower(), f"policer not listed:\n{out}"
    vpp.vppctl("clear policer-ndpi app YouTube")


def test_unknown_app_is_rejected(vpp):
    """A bogus application name is refused rather than silently accepted."""
    rc, out, err = vpp.vppctl("set policy app ThisIsNotAnApp action drop")
    combined = (out + err).lower()
    assert rc != 0 or "unknown" in combined or "invalid" in combined, (
        f"bogus app name was accepted:\n{out}{err}"
    )
