#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME='flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220'
DOCKERFILE_DIR="$SCRIPT_DIR/tools/docker/gui-vm-diagnostic"
PYTHON_VERSION='3.11.9'
PYTHON_INSTALLER_SHA256='5ee42c4eee1e6b4464bb23722f90b45303f79442df63083f05322f1785f5fdde'
BUILD_CONTEXT="${TMPDIR:-/tmp}/flare-fakenet-ng-gui-vm-builder"
PYTHON_INSTALLER="$BUILD_CONTEXT/python-$PYTHON_VERSION-amd64.exe"

mkdir -p "$BUILD_CONTEXT"

echo '[1/3] Downloading/caching the official Windows Python installer...'
if [[ ! -f "$PYTHON_INSTALLER" ]] || \
        ! printf '%s  %s\n' "$PYTHON_INSTALLER_SHA256" "$PYTHON_INSTALLER" | sha256sum --check --status; then
    curl --fail --location --retry 3 \
        --output "$PYTHON_INSTALLER.part" \
        "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-amd64.exe"
    mv "$PYTHON_INSTALLER.part" "$PYTHON_INSTALLER"
fi
printf '%s  %s\n' "$PYTHON_INSTALLER_SHA256" "$PYTHON_INSTALLER" | sha256sum --check

echo '[2/3] Building pinned Wine + Windows Python builder image...'
docker build --file "$DOCKERFILE_DIR/Dockerfile" \
    --build-arg "HOST_UID=$(id -u)" \
    --build-arg "HOST_GID=$(id -g)" \
    --tag "$IMAGE_NAME" "$BUILD_CONTEXT"

echo '[3/3] Building v33 diagnostic package from committed HEAD...'
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$SCRIPT_DIR:/workspace" \
    "$IMAGE_NAME" \
    python3 /workspace/tools/build_gui_vm_diagnostic_wine.py \
        --repo /workspace --source-commit HEAD --output /workspace/dist
