#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME='flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220'
DOCKERFILE_DIR="$SCRIPT_DIR/tools/docker/gui-vm-diagnostic"
PYTHON_VERSION='3.11.9'
PYTHON_INSTALLER_SHA256='5ee42c4eee1e6b4464bb23722f90b45303f79442df63083f05322f1785f5fdde'
MINGIT_VERSION='2.47.1'
MINGIT_BUILD='1'
MINGIT_SHA256='50b04b55425b5c465d076cdb184f63a0cd0f86f6ec8bb4d5860114a713d2c29a'
BUILD_CONTEXT="${TMPDIR:-/tmp}/flare-fakenet-ng-gui-vm-builder"
PYTHON_INSTALLER="$BUILD_CONTEXT/python-$PYTHON_VERSION-amd64.exe"
MINGIT_ZIP="$BUILD_CONTEXT/MinGit-$MINGIT_VERSION-64-bit.zip"
# Incremental gate image: verified pinned base plus MinGit for the
# formal_runtime git fixtures. New tag; never overwrites the base image.
MINGIT_IMAGE_NAME='flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220-mingit'
MODE="${1:-package}"

if [[ $# -gt 1 ]] || [[ "$MODE" != 'package' && "$MODE" != '--image-only' && "$MODE" != '--image-mingit' ]]; then
    echo "Usage: $0 [--image-only|--image-mingit]" >&2
    exit 2
fi

mkdir -p "$BUILD_CONTEXT"

echo '[1/3] Downloading/caching the official Windows Python installer and MinGit...'
if [[ ! -f "$PYTHON_INSTALLER" ]] || \
        ! printf '%s  %s\n' "$PYTHON_INSTALLER_SHA256" "$PYTHON_INSTALLER" | sha256sum --check --status; then
    curl --fail --location --retry 3 \
        --output "$PYTHON_INSTALLER.part" \
        "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-amd64.exe"
    mv "$PYTHON_INSTALLER.part" "$PYTHON_INSTALLER"
fi
printf '%s  %s\n' "$PYTHON_INSTALLER_SHA256" "$PYTHON_INSTALLER" | sha256sum --check

if [[ ! -f "$MINGIT_ZIP" ]] || \
        ! printf '%s  %s\n' "$MINGIT_SHA256" "$MINGIT_ZIP" | sha256sum --check --status; then
    curl --fail --location --retry 3 \
        --output "$MINGIT_ZIP.part" \
        "https://github.com/git-for-windows/git/releases/download/v$MINGIT_VERSION.windows.$MINGIT_BUILD/MinGit-$MINGIT_VERSION-64-bit.zip"
    mv "$MINGIT_ZIP.part" "$MINGIT_ZIP"
fi
printf '%s  %s\n' "$MINGIT_SHA256" "$MINGIT_ZIP" | sha256sum --check

echo '[2/3] Building pinned Wine + Windows Python builder image...'
if [[ "$MODE" == '--image-mingit' ]]; then
    # Incremental image from the verified local base; the pinned tag must
    # resolve to the expected content ID before building on top of it.
    base_id="$(docker image inspect --format '{{.Id}}' "$IMAGE_NAME" 2>/dev/null || true)"
    if [[ "$base_id" != 'sha256:1b33b518a7c71ecd13264f0d1c41faf254e301b8702e2da8ca11376cff700a5e' ]]; then
        echo "Base image identity mismatch for $IMAGE_NAME: $base_id" >&2
        exit 2
    fi
    docker build --file "$DOCKERFILE_DIR/Dockerfile.mingit" \
        --build-arg "MINGIT_VERSION=$MINGIT_VERSION" \
        --build-arg "MINGIT_SHA256=$MINGIT_SHA256" \
        --tag "$MINGIT_IMAGE_NAME" "$BUILD_CONTEXT"
    echo "Incremental builder image ready: $MINGIT_IMAGE_NAME"
    echo "Base image ID: $base_id"
    docker image inspect --format 'Image ID: {{.Id}}' "$MINGIT_IMAGE_NAME"
    exit 0
fi

docker build --file "$DOCKERFILE_DIR/Dockerfile" \
    --build-arg "HOST_UID=$(id -u)" \
    --build-arg "HOST_GID=$(id -g)" \
    --tag "$IMAGE_NAME" "$BUILD_CONTEXT"

if [[ "$MODE" == '--image-only' ]]; then
    echo "Builder image ready: $IMAGE_NAME"
    docker image inspect --format 'Image ID: {{.Id}}' "$IMAGE_NAME"
    exit 0
fi

echo '[3/3] Building v33 diagnostic-03 from HEAD plus the explicit diagnostic overlay...'
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$SCRIPT_DIR:/workspace" \
    "$IMAGE_NAME" \
    python3 /workspace/tools/build_gui_vm_diagnostic_wine.py \
        --repo /workspace --source-commit HEAD --output /workspace/dist \
        --worktree-overlay
