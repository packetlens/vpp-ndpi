"""pytest fixtures for vpp-ndpi tests."""

import os
import shutil
import signal
import subprocess
import tempfile
import time

import pytest


PLUGIN_BUILD_DIR = os.environ.get(
    "PLUGIN_BUILD_DIR",
    os.path.join(os.environ.get("SRC_DIR", "/src"), "build"),
)


def find_plugin_so():
    for root, _, files in os.walk(PLUGIN_BUILD_DIR):
        for f in files:
            if f == "ndpi_plugin.so":
                return os.path.join(root, f)
    return None


def make_startup_conf(plugin_path, run_dir, log_file, prefix):
    plugin_dir = os.path.dirname(plugin_path)
    stats_sock = os.path.join(run_dir, "stats.sock")
    return f"""
unix {{
    nodaemon
    log {log_file}
    full-coredump
    cli-listen {run_dir}/cli.sock
}}

api-trace {{
    on
}}

api-segment {{
    prefix {prefix}
}}

socksvr {{
    socket-name {run_dir}/api.sock
}}

statseg {{
    socket-name {stats_sock}
    size 32m
}}

plugins {{
    path {plugin_dir}:/usr/lib/x86_64-linux-gnu/vpp_plugins
    plugin default {{ disable }}
    plugin ndpi_plugin.so {{ enable }}
}}

ndpi {{
    flows-per-worker 8192
}}
"""


def run_vppctl(run_dir, command, timeout=10):
    """Run a vppctl command. `command` is passed as a single string so
    that multi-word commands with braces (e.g. `packet-generator new { ... }`)
    survive shell argument splitting."""
    sock = f"{run_dir}/cli.sock"
    try:
        result = subprocess.run(
            ["vppctl", "-s", sock, command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "vppctl timeout"


@pytest.fixture(scope="session")
def vpp():
    """Start one VPP instance for the entire test session."""
    plugin = find_plugin_so()
    if plugin is None:
        pytest.fail(f"ndpi_plugin.so not found under {PLUGIN_BUILD_DIR}")

    run_dir = tempfile.mkdtemp(prefix="vpp-ndpi-")
    prefix = os.path.basename(run_dir)
    log_file = os.path.join(run_dir, "vpp.log")
    conf_path = os.path.join(run_dir, "startup.conf")
    with open(conf_path, "w") as f:
        f.write(make_startup_conf(plugin, run_dir, log_file, prefix))

    os.makedirs("/run/vpp", exist_ok=True)
    os.makedirs("/var/log/vpp", exist_ok=True)

    proc = subprocess.Popen(
        ["vpp", "-c", conf_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )

    sock = os.path.join(run_dir, "cli.sock")
    for _ in range(100):
        if os.path.exists(sock):
            break
        if proc.poll() is not None:
            out = (
                proc.stdout.read().decode(errors="replace")
                if proc.stdout
                else ""
            )
            pytest.fail(f"VPP exited early: rc={proc.returncode}\n{out}")
        time.sleep(0.1)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        pytest.fail(f"VPP failed to create CLI socket at {sock}")

    class Handle:
        def __init__(self, run_dir, proc, log_file):
            self.run_dir = run_dir
            self.proc = proc
            self.log_file = log_file
            self.stats_sock = os.path.join(run_dir, "stats.sock")

        def vppctl(self, command):
            return run_vppctl(self.run_dir, command)

    handle = Handle(run_dir, proc, log_file)
    try:
        yield handle
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        shutil.rmtree(run_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def clean(request):
    """No-op between tests; session VPP carries state. Each test uses unique
    stream names (s1, s2, ...) so there is no cross-test stream collision."""
    yield
