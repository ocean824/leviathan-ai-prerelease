#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
desktop="$repo/apps/desktop"
triple="${TARGET_TRIPLE:-}"
if [[ -z "$triple" ]]; then
  case "$(uname -m)" in
    arm64|aarch64) triple="aarch64-apple-darwin" ;;
    x86_64) triple="x86_64-apple-darwin" ;;
    *) echo "Unsupported Mac architecture: $(uname -m)" >&2; exit 2 ;;
  esac
fi
case "$triple" in
  aarch64-apple-darwin) expected="arm64" ;;
  x86_64-apple-darwin) expected="x86_64" ;;
  *) echo "TARGET_TRIPLE must be a supported Darwin target" >&2; exit 2 ;;
esac
if [[ "$(uname -m)" != "$expected" ]]; then
  echo "Build must run natively for $triple (host: $(uname -m))" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Tauri macOS packaging requires a macOS host" >&2
  exit 2
fi
skip_updater_signing="${SKIP_UPDATER_SIGNING:-0}"
if [[ "$skip_updater_signing" != "0" && "$skip_updater_signing" != "1" ]]; then
  echo "SKIP_UPDATER_SIGNING must be 0 or 1" >&2
  exit 2
fi
if [[ "$skip_updater_signing" != "1" && -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  echo "TAURI_SIGNING_PRIVATE_KEY must be provided through the protected release environment" >&2
  exit 2
fi
if [[ "$skip_updater_signing" == "1" ]]; then
  tauri_configs=(--config tauri.macos.conf.json --config tauri.macos.unsigned.conf.json)
else
  tauri_configs=(--config tauri.macos.conf.json)
fi

cd "$repo/apps/terminal"
npm ci --no-audit --no-fund
npm run build
terminal_index="$repo/apps/terminal/dist/index.html"
if [[ ! -f "$terminal_index" ]]; then
  echo "Terminal build output is missing: expected $terminal_index after npm run build" >&2
  exit 1
fi

cd "$repo"
uv run --locked --no-dev --no-build --package leviathan-api --with 'pyinstaller==6.22.3' \
  pyinstaller --noconfirm --clean \
  --distpath "$desktop/sidecar/dist" \
  --workpath "$desktop/sidecar/build" \
  "$desktop/sidecar/leviathan_desktop.spec"
sidecar_dir="$desktop/src-tauri/resources/sidecar"
rm -rf -- "$sidecar_dir"
mkdir -p "$sidecar_dir"
sidecar_name="leviathan-desktop-$triple"
cp -R "$desktop/sidecar/dist/leviathan-desktop/." "$sidecar_dir/"
mv "$sidecar_dir/leviathan-desktop" "$sidecar_dir/$sidecar_name"
chmod 755 "$sidecar_dir/$sidecar_name"

iconset="$desktop/src-tauri/icons/icon.iconset"
mkdir -p "$iconset"
sips -s format png "$desktop/src-tauri/icons/icon.ico" --out "$iconset/icon_512x512.png" >/dev/null
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$iconset/icon_512x512.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  if [[ "$double" -le 1024 ]]; then
    sips -z "$double" "$double" "$iconset/icon_512x512.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
  fi
done
iconutil -c icns "$iconset" -o "$desktop/src-tauri/icons/icon.icns"
cd "$desktop/src-tauri"
npx --yes '@tauri-apps/cli@2.12.0' build --target "$triple" "${tauri_configs[@]}"

version="$(python3 -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["package"]["version"])' "$desktop/src-tauri/Cargo.toml")"
bundle="$desktop/src-tauri/target/$triple/release/bundle/macos"
if [[ "$skip_updater_signing" == "1" ]]; then
  dmg_bundle="$desktop/src-tauri/target/$triple/release/bundle/dmg"
  dmg="$(find "$dmg_bundle" -maxdepth 1 -type f -name '*.dmg' -print -quit)"
  [[ -n "$dmg" && -f "$dmg" ]] || { echo "macOS DMG is missing under $dmg_bundle" >&2; exit 1; }
  echo "Built unsigned, unnotarized $triple app in $bundle and DMG in $dmg_bundle (updater artifacts disabled)"
  exit 0
fi

archive="$(find "$bundle" -maxdepth 1 -type f -name '*.app.tar.gz' -print -quit)"
[[ -n "$archive" && -f "$archive.sig" ]] || { echo "Signed app updater artifact is missing" >&2; exit 1; }
arch="${triple%-apple-darwin}"
if [[ "$arch" == "aarch64" ]]; then feed_platform="darwin-aarch64"; else feed_platform="darwin-x86_64"; fi
artifact="LeviathanAI_${version}_${arch}.app.tar.gz"
cp "$archive" "$bundle/$artifact"
cp "$archive.sig" "$bundle/$artifact.sig"
uv run --locked --no-dev --package leviathan-api python "$repo/infra/release/feed_manifest.py" \
  --bundle-dir "$bundle" --feed "$repo/infra/release/feed.json" \
  --version "$version" --notes 'Leviathan AI macOS update' \
  --pub-date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --require-signature \
  --artifact "$feed_platform=$artifact" \
  --platform-signature "$feed_platform=$bundle/$artifact.sig"
if [[ -n "${OTHER_DARWIN_ARTIFACT:-}" || -n "${OTHER_DARWIN_SIGNATURE:-}" ]]; then
  [[ -f "${OTHER_DARWIN_ARTIFACT:-}" && -f "${OTHER_DARWIN_SIGNATURE:-}" ]] || {
    echo "OTHER_DARWIN_ARTIFACT and OTHER_DARWIN_SIGNATURE must both name existing files" >&2
    exit 2
  }
  if [[ "$feed_platform" == "darwin-aarch64" ]]; then other_platform="darwin-x86_64"; else other_platform="darwin-aarch64"; fi
  uv run --locked --no-dev --package leviathan-api python "$repo/infra/release/feed_manifest.py" \
    --bundle-dir "$bundle" --feed "$repo/infra/release/feed.json" \
    --version "$version" --notes 'Leviathan AI macOS update' \
    --pub-date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --require-signature \
    --artifact "$feed_platform=$artifact" \
    --platform-signature "$feed_platform=$bundle/$artifact.sig" \
    --artifact "$other_platform=$(basename "$OTHER_DARWIN_ARTIFACT")" \
    --platform-signature "$other_platform=$OTHER_DARWIN_SIGNATURE"
  cp "$OTHER_DARWIN_ARTIFACT" "$bundle/$(basename "$OTHER_DARWIN_ARTIFACT")"
  cp "$OTHER_DARWIN_SIGNATURE" "$bundle/$(basename "$OTHER_DARWIN_ARTIFACT").sig"
fi
find "$bundle" -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' -print0 | xargs -0 shasum -a 256 > "$bundle/SHA256SUMS.txt"
echo "Built unsigned, unnotarized $triple app and DMG in $bundle"
