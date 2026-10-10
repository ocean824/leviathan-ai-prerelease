#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
  echo "Usage: $0 <bundled-sidecar-executable>" >&2
  exit 2
fi

sidecar="$1"
temporary_home="$(mktemp -d)"
mkdir -p "$temporary_home/home"
shutdown_file="$temporary_home/shutdown"
log_file="$temporary_home/sidecar.log"
export HOME="$temporary_home/home"
export LEVIATHAN_DESKTOP_CAPABILITY="$(python3 -c 'print("a" * 64)')"
export LEVIATHAN_DATA_ROOT_PREEXISTED=0
profile="$HOME/Library/Application Support/LeviathanAI"
[[ ! -e "$profile" ]] || { echo "Smoke-test profile must start absent" >&2; exit 1; }
export LEVIATHAN_DATA_ROOT_ENTRY_SHA256="$(python3 - "$profile" <<'PY'
import hashlib
import sys
from pathlib import Path

profile = Path(sys.argv[1])
digest = hashlib.sha256()
for directory, label in ((profile, b"root/"), (profile / "data", b"data/")):
    if not directory.is_dir():
        continue
    entries = []
    for path in directory.iterdir():
        encoded = path.name.encode("utf-16le", "surrogatepass")
        units = tuple(
            int.from_bytes(encoded[index:index + 2], "little")
            for index in range(0, len(encoded), 2)
        )
        entries.append((units, encoded))
    for _, encoded in sorted(entries):
        digest.update(label)
        digest.update(encoded)
        digest.update(b"\x00\x00")
print(digest.hexdigest())
PY
)"
export LEVIATHAN_DESKTOP_SHUTDOWN_FILE="$shutdown_file"

"$sidecar" >"$log_file" 2>&1 &
sidecar_pid=$!
cleanup() {
  touch "$shutdown_file"
  if kill -0 "$sidecar_pid" 2>/dev/null; then
    kill -TERM "$sidecar_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$sidecar_pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -KILL "$sidecar_pid" 2>/dev/null || true
  fi
  wait "$sidecar_pid" 2>/dev/null || true
  rm -rf "$temporary_home"
}
trap cleanup EXIT

port=""
for _ in $(seq 1 60); do
  if ! kill -0 "$sidecar_pid" 2>/dev/null; then
    cat "$log_file" >&2
    echo "Sidecar exited before becoming ready" >&2
    exit 1
  fi
  port="$(sed -n 's/^LEVIATHAN_READY port=//p' "$log_file" | tail -n 1)"
  [[ -n "$port" ]] && break
  sleep 0.5
done
[[ -n "$port" ]] || { cat "$log_file" >&2; echo "Sidecar startup timed out" >&2; exit 1; }
curl --fail --silent --show-error --connect-timeout 2 --max-time 5 --retry 6 --retry-delay 1 --retry-max-time 40 "http://127.0.0.1:$port/api/health"
printf '\nSidecar loopback health check passed.\n'
touch "$shutdown_file"
wait "$sidecar_pid"
