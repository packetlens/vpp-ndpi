#!/usr/bin/env bash
# Build the vpp-ndpi base Docker image (VPP debug .debs + libndpi-dev + tools).
#
# Steps:
#   1. Initialize VPP submodule (unless --skip-submodule)
#   2. Build VPP debug .deb packages (unless --skip-debs)
#   3. Build Dockerfile.base with the specified tag
#   4. Optionally push the image (--push)
#
# Usage:
#   ./scripts/build-base.sh                            # local default
#   ./scripts/build-base.sh --tag ghcr.io/org/img:base --push  # CI
#   ./scripts/build-base.sh --skip-debs                # rebuild image only
#   ./scripts/build-base.sh --ensure                   # build only if missing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Defaults
TAG="${IMAGE_TAG:-vpp-ndpi-dev:base}"
PUSH=false
SKIP_SUBMODULE=false
SKIP_DEBS=false
ENSURE=false

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)            TAG="$2"; shift ;;
    --push)           PUSH=true ;;
    --skip-submodule) SKIP_SUBMODULE=true ;;
    --skip-debs)      SKIP_DEBS=true ;;
    --ensure)         ENSURE=true ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

if [ "$ENSURE" = true ] && docker image inspect "$TAG" &>/dev/null; then
  exit 0
fi

if [ "$SKIP_SUBMODULE" = false ]; then
  echo "==> Initializing VPP submodule..."
  git submodule update --init --recursive
fi

if [ "$SKIP_DEBS" = false ]; then
  echo "==> Building VPP debug .deb packages (this takes ~30 min)..."
  "$SCRIPT_DIR/build-vpp-debs.sh"
fi

echo "==> Building base image as $TAG..."
docker build -f Dockerfile.base -t "$TAG" .

if [ "$PUSH" = true ]; then
  echo "==> Pushing $TAG..."
  docker push "$TAG"
fi

echo ""
echo "==> Base image ready: $TAG"
