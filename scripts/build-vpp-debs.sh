#!/usr/bin/env bash
# Build VPP debug .deb packages using the VPP submodule.
#
# Mounts VPP source read-only, copies to a writable dir inside the container,
# builds .debs there. Host submodule stays clean — no root-owned artifacts.
#
# Outputs .deb files to debs/ in the project root.
# These are then used by Dockerfile.base to create the base image.
#
# Usage:  ./scripts/build-vpp-debs.sh

set -euo pipefail
cd "$(dirname "$0")/.."

DEBS_DIR="$(pwd)/debs"
mkdir -p "$DEBS_DIR"

echo "==> Building VPP debug .deb packages..."
echo "    VPP source: $(pwd)/vpp (mounted read-only)"
echo "    Output dir: $DEBS_DIR"

docker run --rm \
  --mount type=bind,source="$(pwd)/vpp",target=/opt/vpp-src,readonly \
  -v "$DEBS_DIR:/debs" \
  ubuntu:24.04 \
  bash -c '
    set -ex
    export DEBIAN_FRONTEND=noninteractive

    echo "==> Copying VPP source..."
    cp -a /opt/vpp-src /opt/vpp
    rm -rf /opt/vpp/.git

    apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      git ca-certificates sudo curl build-essential make

    git config --global --add safe.directory /opt/vpp
    cd /opt/vpp
    git init -q
    git config user.email "build@packetlens"
    git config user.name "Builder"
    git add Makefile build/ build-root/Makefile build-root/*.mk \
            build-root/scripts/ src/pkg/ 2>/dev/null || true
    git commit -q -m "stub" --allow-empty
    git tag -a v25.10 -m "VPP 25.10"

    echo "==> Installing VPP dependencies..."
    (yes || true) | make -C /opt/vpp install-dep
    echo "==> Installing VPP external dependencies..."
    (yes || true) | make -C /opt/vpp install-ext-deps

    echo "==> Building debug .deb packages..."
    NPROC=$(nproc)
    make -C /opt/vpp pkg-deb-debug -j"$NPROC"

    find /opt/vpp/build-root -name "*.deb" -exec cp {} /debs/ \;
    echo ""
    echo "==> .deb packages:"
    ls -lh /debs/*.deb
  '

echo ""
echo "==> Done. .deb files in: $DEBS_DIR"
ls -lh "$DEBS_DIR"/*.deb
