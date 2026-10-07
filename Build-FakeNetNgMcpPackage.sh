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
if [[ ! "$SHARDS" =~ ^[0-9]+$ ]]; then
    echo "SHARDS must be a nonnegative integer" >&2
    exit 2
fi

run_builder() {
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --env BUILDER_IMAGE_ID="$BUILDER_IMAGE_ID" \
        --volume "$SCRIPT_DIR:/workspace" \
        "$IMAGE_NAME" python3 /workspace/tools/build_fakenetng_mcp_wine.py "$@"
}

if [[ "$SHARDS" -ge 0 ]]; then
    SOURCE_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse "$SOURCE_COMMIT^{commit}")"
    gate_count="$SHARDS"
    if [[ "$gate_count" -eq 0 ]]; then gate_count=1; fi
    echo "Building fakenetng-mcp candidate with $IMAGE_NAME from immutable source $SOURCE_COMMIT ($SHARDS gate shards, layer=$LAYER)"
    mkdir -p "$SCRIPT_DIR/Logs/fakenetng-mcp/builds"
    shard_dir="$(mktemp -d "$SCRIPT_DIR/Logs/fakenetng-mcp/builds/merged-${SOURCE_COMMIT:0:8}-$LAYER-XXXXXXXX")"
    pids=()
    for ((i = 0; i < gate_count; i++)); do
        shard_args=()
        if [[ "$SHARDS" -gt 0 ]]; then shard_args=(--shard-index "$i" --shard-count "$SHARDS"); fi
        run_builder --repo /workspace --source-commit "$SOURCE_COMMIT" \
            --output "$(to_container_path "$shard_dir")" \
            --gate-only --layer "$LAYER" "${shard_args[@]}" \
            > "$shard_dir/shard-$i.log" 2>&1 &
        pids+=($!)
    done
    failed=0
    for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
    if [[ "$failed" -ne 0 ]]; then
        echo "Gate shards failed; see $shard_dir/shard-*.log" >&2
        exit 1
    fi
    merge_args=(--repo "$SCRIPT_DIR" --source-commit "$SOURCE_COMMIT" --gate-merge
                --layer "$LAYER" --shard-count "$gate_count" --builder-image-id "$BUILDER_IMAGE_ID"
                --qualification "$shard_dir/qualification.json")
    for ((i = 0; i < gate_count; i++)); do
        receipt="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).read().splitlines()[-1])["gate"]["receipt"]["path"])' "$shard_dir/shard-$i.log")"
        merge_args+=(--receipt "$SCRIPT_DIR/$receipt")
    done
    if [[ "$LAYER" == core ]]; then
        "$SCRIPT_DIR/.venv-mcp-runners/bin/python" "$SCRIPT_DIR/tools/build_fakenetng_mcp_wine.py" \
            --repo "$SCRIPT_DIR" --source-commit "$SOURCE_COMMIT" --host-only --layer core \
            --builder-image-id "$BUILDER_IMAGE_ID" > "$shard_dir/host.log" 2>&1
        host_receipt="$(sed -n 's/^Host receipt: //p' "$shard_dir/host.log")"
        merge_args+=(--host-receipt "$host_receipt")
    fi
    python3 "$SCRIPT_DIR/tools/build_fakenetng_mcp_wine.py" \
        "${merge_args[@]}" \
        | tee "$shard_dir/gate-merged.json"
    qualification_sha="$(sha256sum "$shard_dir/qualification.json")"
    qualification_sha="${qualification_sha%% *}"
    echo "Gate green; packaging once from $SOURCE_COMMIT"
    package_args=(--repo /workspace --source-commit "$SOURCE_COMMIT"
                  --output "$(to_container_path "$OUTPUT_ROOT")" --layer "$LAYER" --package-only
                  --qualification "$(to_container_path "$shard_dir/qualification.json")"
                  --qualification-sha256 "$qualification_sha")
    if [[ -n "$OUTPUT_DIRECTORY" ]]; then package_args+=(--output-directory "$(to_container_path "$OUTPUT_DIRECTORY")"); fi
    run_builder "${package_args[@]}"
    exit $?
fi
