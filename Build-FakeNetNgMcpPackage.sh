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

# SHARDS>0 runs the Windows gate as parallel shard containers, merges the
# verdicts host-side, then packages once after a green gate. SHARDS=0 keeps
# the classic single serial build.
SHARDS="${SHARDS:-0}"
LAYER="${LAYER:-full}"

run_builder() {
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "$SCRIPT_DIR:/workspace" \
        "$IMAGE_NAME" python3 /workspace/tools/build_fakenetng_mcp_wine.py "$@"
}

if [[ "$SHARDS" -gt 0 ]]; then
    echo "Building fakenetng-mcp candidate with $IMAGE_NAME from immutable source $SOURCE_COMMIT ($SHARDS gate shards, layer=$LAYER)"
    shard_dir="$SCRIPT_DIR/Logs/fakenetng-mcp/builds/merged-$SOURCE_COMMIT-$LAYER"
    rm -rf "$shard_dir"; mkdir -p "$shard_dir"
    pids=()
    for ((i = 0; i < SHARDS; i++)); do
        out="$(to_container_path "$shard_dir")/shard-$i"
        run_builder --repo /workspace --source-commit "$SOURCE_COMMIT" \
            --output "$(to_container_path "$shard_dir")" --output-directory "$out" \
            --gate-only --layer "$LAYER" --shard-index "$i" --shard-count "$SHARDS" \
            > "$shard_dir/shard-$i.log" 2>&1 &
        pids+=($!)
    done
    failed=0
    for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
    if [[ "$failed" -ne 0 ]]; then
        echo "Gate shards failed; see $shard_dir/shard-*.log" >&2
        exit 1
    fi
    find "$shard_dir" -name 'windows-pytest-main-shard-*.xml' -exec mv {} "$shard_dir/" \;
    find "$shard_dir" -name 'windows-pytest-http.xml' -exec mv {} "$shard_dir/" \;
    python3 "$SCRIPT_DIR/tools/build_fakenetng_mcp_wine.py" \
        --repo "$SCRIPT_DIR" --gate-merge --merge-dir "$shard_dir" \
        | tee "$shard_dir/gate-merged.json"
    echo "Gate green; packaging once from $SOURCE_COMMIT"
    run_builder --repo /workspace --source-commit "$SOURCE_COMMIT" \
        --output "$(to_container_path "$OUTPUT_ROOT")" \
        $(if [[ -n "$OUTPUT_DIRECTORY" ]]; then echo --output-directory "$(to_container_path "$OUTPUT_DIRECTORY")"; fi) \
        --package-only
    exit $?
fi

args=(--repo /workspace --source-commit "$SOURCE_COMMIT"
      --output "$(to_container_path "$OUTPUT_ROOT")")
if [[ -n "$OUTPUT_DIRECTORY" ]]; then
    args+=(--output-directory "$(to_container_path "$OUTPUT_DIRECTORY")")
fi

echo "Building fakenetng-mcp candidate with $IMAGE_NAME from immutable source $SOURCE_COMMIT"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$SCRIPT_DIR:/workspace" \
    "$IMAGE_NAME" python3 /workspace/tools/build_fakenetng_mcp_wine.py "${args[@]}"
