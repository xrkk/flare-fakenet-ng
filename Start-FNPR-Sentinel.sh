#!/usr/bin/env bash

set -uo pipefail

readonly BIND_IPV4='192.168.204.1'
readonly LISTEN_PORT='443'

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)" || exit 1
readonly SCRIPT_DIR
readonly SENTINEL_PATH="$SCRIPT_DIR/fnpr_sentinel.py"
readonly LOG_ROOT="$SCRIPT_DIR/dist/Logs"
readonly STAMP="$(date '+%Y%m%d-%H%M%S')"
readonly LOG_DIR="$LOG_ROOT/fnpr-sentinel-$STAMP"
readonly LOG_PATH="$LOG_DIR/sentinel.log"
readonly CONSOLE_LOG="$LOG_DIR/console.log"
readonly START_ERROR_LOG="$LOG_DIR/start-error.log"
readonly PYTHON_CMD="${FNPR_PYTHON:-python3}"

mkdir -p -- "$LOG_DIR" || {
    printf 'START FAILED: cannot create log directory: %s\n' "$LOG_DIR" >&2
    exit 1
}

fail() {
    local message="$1"
    printf 'START FAILED: %s\n' "$message" | tee -a "$START_ERROR_LOG" >&2
    printf 'Plain logs: %s\n' "$LOG_DIR" >&2
    exit 1
}

[[ -f "$SENTINEL_PATH" ]] || \
    fail "Listener script is missing: $SENTINEL_PATH"

command -v -- "$PYTHON_CMD" >/dev/null 2>&1 || \
    fail "Python 3 was not found: $PYTHON_CMD. No dependency is downloaded automatically."

python_major="$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)' 2>/dev/null)" || \
    fail "Unable to execute Python: $PYTHON_CMD"
[[ "$python_major" == '3' ]] || \
    fail "Python 3 is required. No dependency is downloaded automatically."

command -v ip >/dev/null 2>&1 || \
    fail "The Linux ip command is required for the read-only address check."

assigned_count="$(ip -4 -o addr show | awk -v target="$BIND_IPV4" '
    {
        split($4, address, "/")
        if (address[1] == target) {
            count++
        }
    }
    END { print count + 0 }
')" || fail "Unable to inspect host IPv4 assignments."

[[ "$assigned_count" == '1' ]] || \
    fail "Required host-only IPv4 $BIND_IPV4 is not uniquely assigned on this host."

bind_error="$LOG_DIR/bind-check.log"
if ! "$PYTHON_CMD" -c '
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
finally:
    sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
finally:
    sock.close()
' "$BIND_IPV4" "$LISTEN_PORT" 2>"$bind_error"; then
    fail "Cannot bind TCP+UDP/$LISTEN_PORT on $BIND_IPV4; a port may be occupied or the current user may lack permission."
fi
rm -f -- "$bind_error"

printf 'Starting FNPR/1 TCP+UDP sentinel on %s:%s\n' "$BIND_IPV4" "$LISTEN_PORT"
printf '%s\n' 'This listener accepts only bounded FNPR/1 nonce probes.'
printf '%s\n' 'Press Ctrl+C to stop.'
printf 'Plain log: %s\n\n' "$LOG_PATH"

"$PYTHON_CMD" -u "$SENTINEL_PATH" --log "$LOG_PATH" 2>&1 |
    tee "$CONSOLE_LOG"
exit_code=${PIPESTATUS[0]}

if (( exit_code != 0 )); then
    fail "FNPR/1 sentinel exited with code $exit_code."
fi

exit 0
