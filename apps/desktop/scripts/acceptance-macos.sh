#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS acceptance requires a macOS host" >&2
  exit 2
fi
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
desktop="$repo/apps/desktop"
host_arch="$(uname -m)"
if [[ "$host_arch" == "arm64" ]]; then triple="aarch64-apple-darwin"; else triple="x86_64-apple-darwin"; fi
bundle_dir="${BUNDLE_DIR:-$desktop/src-tauri/target/$triple/release/bundle/macos}"
dmg="${DMG_PATH:-$(find "$bundle_dir" -maxdepth 1 -name '*.dmg' -print -quit)}"
[[ -n "$dmg" && -f "$dmg" ]] || { echo "DMG_PATH or built DMG required" >&2; exit 2; }
mount="$(mktemp -d)"
install_root="${INSTALL_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/leviathan-pkg-mac-XXXXXX")}"
app="$install_root/Leviathan AI.app"
mkdir -p "$install_root"
device="$(hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mount" | awk -v path="$mount" '$0 ~ path {print $1; exit}')"
cleanup() { [[ -z "${device:-}" ]] || hdiutil detach "$mount" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ditto "$mount/Leviathan AI.app" "$app"
echo "If Gatekeeper blocks first launch, Control-click '$app', choose Open, then confirm Open in the dialog."
open "$app"
echo "Complete sign-in in Leviathan AI, then leave the runtime open."
for _ in {1..600}; do
  port="$(find "$HOME/Library/Application Support/LeviathanAI" -maxdepth 1 -name 'desktop-sidecar.log' -exec grep -oE 'LEVIATHAN_READY port=[0-9]+' {} \; 2>/dev/null | tail -1 | cut -d= -f2 || true)"
  [[ -z "$port" ]] || break
  sleep 1
done
[[ -n "${port:-}" ]] || { echo "Sign-in gated sidecar did not start after authenticated unlock" >&2; exit 1; }
curl --fail --silent "http://127.0.0.1:$port/api/health" >/dev/null
open "$app"
sleep 2
[[ "$(pgrep -f 'Leviathan AI.app/Contents/MacOS' | wc -l | tr -d ' ')" -le 1 ]] || { echo "Duplicate app process detected" >&2; exit 1; }
echo "Manual acceptance still required: sign-in denial/cold start, sidecar crash/restart prompt, open-order updater deferral, signed newer-only update, Gatekeeper first-open, and app removal with retained data."
echo "Acceptance host: $(sw_vers -productVersion) $(uname -m); app: $app"
