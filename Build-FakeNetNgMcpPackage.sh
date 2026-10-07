#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# The pinned base image; BUILDER_IMAGE may explicitly select the incremental
# MinGit gate image built by ./Build-GuiVmDiagnosticPackage.sh --image-mingit.
IMAGE_NAME="${BUILDER_IMAGE:-flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220}"
SOURCE_COMMIT="${SOURCE_COMMIT:-HEAD}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$SCRIPT_DIR/dist}"

if [[ $# -gt 3 ]]; then
    echo "Usage: $0 [source-commit] [output-root] [output-directory]" >&2
    exit 2
fi
if [[ $# -ge 1 ]]; then SOURCE_COMMIT="$1"; fi
if [[ $# -ge 2 ]]; then OUTPUT_ROOT="$2"; fi
OUTPUT_DIRECTORY=""
if [[ $# -ge 3 ]]; then OUTPUT_DIRECTORY="$3"; fi

if [[ "$OUTPUT_ROOT" != /* ]]; then OUTPUT_ROOT="$SCRIPT_DIR/$OUTPUT_ROOT"; fi
if [[ -n "$OUTPUT_DIRECTORY" && "$OUTPUT_DIRECTORY" != /* ]]; then
    OUTPUT_DIRECTORY="$SCRIPT_DIR/$OUTPUT_DIRECTORY"
fi

to_container_path() {
    local path="$1"
    if [[ "$path" == "$SCRIPT_DIR" ]]; then
        echo /workspace
    elif [[ "$path" == "$SCRIPT_DIR/"* ]]; then
        echo "/workspace/${path#"$SCRIPT_DIR/"}"
    else
        echo "Output paths must stay under the repository root: $path" >&2
        exit 2
    fi
}

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Pinned builder image is unavailable: $IMAGE_NAME" >&2
    echo "Run ./Build-GuiVmDiagnosticPackage.sh --image-only (or --image-mingit), then retry." >&2
    exit 2
fi
# Record the resolved content identity so the build log pins the image by
# digest, not just by tag.
BUILDER_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_NAME")"
echo "Builder image: $IMAGE_NAME ($BUILDER_IMAGE_ID)"

args=(python3 /workspace/tools/build_fakenetng_mcp_wine.py
      --repo /workspace --source-commit "$SOURCE_COMMIT"
      --output "$(to_container_path "$OUTPUT_ROOT")")
if [[ -n "$OUTPUT_DIRECTORY" ]]; then
    args+=(--output-directory "$(to_container_path "$OUTPUT_DIRECTORY")")
fi

echo "Building fakenetng-mcp candidate with $IMAGE_NAME from immutable source $SOURCE_COMMIT"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$SCRIPT_DIR:/workspace" \
    "$IMAGE_NAME" "${args[@]}"
