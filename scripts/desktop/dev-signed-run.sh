#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/desktop/dev-signed-run.sh [--profile PATH] [--no-run]

Build the debug desktop binary, assemble a minimal .app bundle with the
entitlements and provisioning profile required by the DataProtection
keychain (Secure Enclave seal key), stage the bundled runtime (runned
daemon + runne CLI) into the bundle, and launch it.

Options:
  --profile PATH  Apple-signed Developer ID provisioning profile authorizing
                  keychain-access-groups; copied to
                  Contents/embedded.provisionprofile. Required for launch.
  --no-run        Build and assemble the bundle; do not launch.
  -h, --help      Show this help

Environment:
  RUNNE_MACOS_SIGNING_IDENTITY  Override signing identity (default: first
                                valid Developer ID Application identity).
  CARGO_PROFILE_DEV_DEBUG       Defaults to 0 in this script to keep the
                                target dir small; override to change.

Exit codes:
  0  success (or assembled with --no-run)
  1  build/sign/assembly failure
  2  usage error
  3  launch refused: --profile was not provided
USAGE
}

profile=""
no_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then echo "error: --profile requires a value" >&2; exit 2; fi
      profile="$2"
      shift 2
      ;;
    --no-run) no_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) echo "error: unexpected argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"

cargo build -p runne-desktop -p runne-daemon -p runne-cli

binary="target/debug/runne-desktop"
if [[ ! -f "$binary" ]]; then
  echo "error: built desktop binary not found: $binary" >&2
  exit 1
fi

runtime_bins=(target/debug/runned target/debug/runne)
for rt in "${runtime_bins[@]}"; do
  if [[ ! -f "$rt" ]]; then
    echo "error: built runtime binary not found: $rt" >&2
    exit 1
  fi
done

bundle="target/dev-bundle/RunneDev.app"
rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS"
install -m 0755 "$binary" "$bundle/Contents/MacOS/runne-desktop"

version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' \
  apps/desktop/src-tauri/tauri.conf.json) || {
  echo "error: failed to read .version from apps/desktop/src-tauri/tauri.conf.json" >&2
  exit 1
}

cat <<EOF > "$bundle/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.runne.desktop</string>
  <key>CFBundleExecutable</key><string>runne-desktop</string>
  <key>CFBundleName</key><string>RunneDev</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
</dict>
</plist>
EOF

identity="${RUNNE_MACOS_SIGNING_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk '/Developer ID Application/ { print $2; exit }')
  if [[ -z "$identity" ]]; then
    echo "error: no valid Developer ID Application identity found" >&2
    echo "Set RUNNE_MACOS_SIGNING_IDENTITY or import a Developer ID certificate into keychain." >&2
    exit 1
  fi
fi

# Stage the bundled runtime (runned + runne CLI) next to the desktop
# executable so discover_bundled_runtime finds them. Nested code must be
# signed (plain, no entitlements) before the outer bundle signature.
for rt in "${runtime_bins[@]}"; do
  staged="$bundle/Contents/MacOS/$(basename "$rt")"
  install -m 0755 "$rt" "$staged"
  codesign --sign "$identity" --force --options runtime --timestamp "$staged"
  # NOTE: --quiet is not supported by this codesign; plain --verify is
  # silent on success and non-zero on failure.
  codesign --verify "$staged"
done

if [[ -n "$profile" ]]; then
  if [[ ! -f "$profile" ]]; then
    echo "error: provisioning profile not found: $profile" >&2
    exit 1
  fi
  cp "$profile" "$bundle/Contents/embedded.provisionprofile"
  codesign --sign "$identity" --force --options runtime --timestamp \
    --entitlements apps/desktop/src-tauri/macos/desktop.entitlements "$bundle"
  codesign --verify --verbose "$bundle"
  echo "Signed bundle: $bundle"
else
  codesign --sign "$identity" --force --options runtime --timestamp "$bundle"
  codesign --verify --verbose "$bundle"
  cat <<'WARNING'
warning: bundle signed WITHOUT entitlements and without an embedded
provisioning profile. The DataProtection keychain is unavailable, so the
app will refuse to open ("anchored mutation admission is unavailable").
This mode is only useful for non-keychain checks.
WARNING
fi

if [[ "$no_run" -eq 1 ]]; then
  exit 0
fi

if [[ -z "$profile" ]]; then
  cat >&2 <<'REFUSAL'
error: launch refused: the app cannot open its secure store without an
embedded provisioning profile. Obtain a Developer ID provisioning profile
for App ID com.runne.desktop with keychain group
758F9Z45SR.com.runne.desktop and pass it via --profile.
REFUSAL
  exit 3
fi

open "$bundle"
echo "Launched: $bundle"
