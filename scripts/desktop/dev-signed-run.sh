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
  --credential-service  Stage the credential-service helper, its LaunchAgent
                        plist, and the native-enrollment JSONs into the bundle
                        (helper is signed before the outer bundle signature).
  --credential-service-profile PATH
                        Developer ID provisioning profile for com.runne.
                        credential-service (default: ~/Downloads/
                        Runne_Credential_Service_Developer_ID.provisionprofile).
  --no-run        Build and assemble the bundle; do not launch.
  --reset-runtime  Clear derived bundled-runtime state (activation + daemon session) before launch; required after rebuilding the signed binaries, because their identity change invalidates the previous activation
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
reset_runtime=0
credential_service=0
cs_profile=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then echo "error: --profile requires a value" >&2; exit 2; fi
      profile="$2"
      shift 2
      ;;
    --no-run) no_run=1; shift ;;
    --reset-runtime) reset_runtime=1; shift ;;
    --credential-service) credential_service=1; shift ;;
    --credential-service-profile)
      if [[ $# -lt 2 ]]; then echo "error: --credential-service-profile requires a value" >&2; exit 2; fi
      cs_profile="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) echo "error: unexpected argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"

# Without --features desktop-protected the daemon cannot answer the protected first-activation protocol and exits(2) on spawn (release stage_bundled_daemon.mjs builds with the same feature); daemon builds last so target/debug/runned has it.
cargo build -p runne-desktop -p runne-cli
cargo build -p runne-daemon --features desktop-protected

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

bundle="target/dev-bundle/Runne.app"
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
  <key>CFBundleName</key><string>Runne</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
</dict>
</plist>
EOF

# Stage the UI contract file (mirrors tauri.conf.json bundle.resources mapping
# ../../../contracts/gocode-ui-client-2/bundle.json ->
# Contents/Resources/contracts/gocode-ui-client-2/bundle.json).
contract_src="contracts/gocode-ui-client-2/bundle.json"
[[ -f "$contract_src" ]] || { echo "error: contract file not found: $contract_src" >&2; exit 1; }
install -d -m 0755 "$bundle/Contents/Resources/contracts/gocode-ui-client-2"
install -m 0644 "$contract_src" "$bundle/Contents/Resources/contracts/gocode-ui-client-2/bundle.json"

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
xattr -cr "$bundle" 2>/dev/null || true  # clear LaunchServices provenance xattrs (codesign EIO)
for rt in "${runtime_bins[@]}"; do
  staged="$bundle/Contents/MacOS/$(basename "$rt")"
  install -m 0755 "$rt" "$staged"
  codesign --sign "$identity" --force --options runtime --timestamp "$staged"
  # NOTE: --quiet is not supported by this codesign; plain --verify is
  # silent on success and non-zero on failure.
  codesign --verify "$staged"
done

# Stage the credential-service helper (packaging parity with the release bundle
# layout in tauri.conf.json bundle.macOS.files); signed before the outer signature.
if [[ "$credential_service" -eq 1 ]]; then
  staged_helper="apps/desktop/src-tauri/macos/credential-service/staged/RunneCredentialService.app"
  helper="$bundle/Contents/Library/Helpers/RunneCredentialService.app"
  [[ -d "$staged_helper" ]] || { echo "error: staged credential-service helper not found: $staged_helper (run: pnpm --filter @runne/desktop stage:credential-service)" >&2; exit 1; }
  rm -rf "$helper"; mkdir -p "$bundle/Contents/Library/Helpers"; cp -R "$staged_helper" "$helper"
  cs_default="$HOME/Downloads/Runne_Credential_Service_Developer_ID.provisionprofile"
  if [[ -z "$cs_profile" && -f "$cs_default" ]]; then cs_profile="$cs_default"; fi
  if [[ -n "$cs_profile" ]]; then
    [[ -f "$cs_profile" ]] || { echo "error: credential-service provisioning profile not found: $cs_profile" >&2; exit 1; }
    cp "$cs_profile" "$helper/Contents/embedded.provisionprofile"
    codesign --sign "$identity" --force --options runtime --timestamp \
      --entitlements apps/desktop/src-tauri/macos/credential-service.entitlements "$helper"
  else
    echo "warning: no credential-service provisioning profile (default: $cs_default); signing the helper WITHOUT entitlements/profile: it will not be admitted by the daemon's XPC identity checks (packaging parity only)" >&2
    codesign --sign "$identity" --force --options runtime --timestamp "$helper"
  fi
  codesign --verify "$helper"
  mkdir -p "$bundle/Contents/Library/LaunchAgents" "$bundle/Contents/Resources/native-enrollment"
  install -m 0644 apps/desktop/src-tauri/macos/com.runne.credential-service.plist "$bundle/Contents/Library/LaunchAgents/com.runne.credential-service.plist"
  install -m 0644 apps/desktop/src-tauri/macos/native-enrollment/staged/xpc-protocol-v1.json "$bundle/Contents/Resources/native-enrollment/xpc-protocol-v1.json"
  install -m 0644 apps/desktop/src-tauri/macos/native-enrollment/staged/release-candidate-binding.json "$bundle/Contents/Resources/native-enrollment/release-candidate-binding.json"
fi

if [[ -n "$profile" ]]; then
  if [[ ! -f "$profile" ]]; then
    echo "error: provisioning profile not found: $profile" >&2
    exit 1
  fi
  cp "$profile" "$bundle/Contents/embedded.provisionprofile"
  xattr -cr "$bundle" 2>/dev/null || true  # clear LaunchServices provenance xattrs (codesign EIO)
  codesign --sign "$identity" --force --options runtime --timestamp \
    --entitlements apps/desktop/src-tauri/macos/desktop.entitlements "$bundle"
  codesign --verify --verbose "$bundle"
  echo "Signed bundle: $bundle"
else
  xattr -cr "$bundle" 2>/dev/null || true  # clear LaunchServices provenance xattrs (codesign EIO)
  codesign --sign "$identity" --force --options runtime --timestamp "$bundle"
  codesign --verify --verbose "$bundle"
  cat <<'WARNING'
warning: bundle signed WITHOUT entitlements and without an embedded
provisioning profile. The DataProtection keychain is unavailable, so the
app will refuse to open ("anchored mutation admission is unavailable").
This mode is only useful for non-keychain checks.
WARNING
fi

if [[ "$reset_runtime" -eq 1 ]]; then
  bundled_runtime_state="$HOME/Library/Application Support/com.runne.desktop/bundled-runtime"
  # Clear only the two derived state dirs; never touch bundled-runtime itself.
  rm -rf "$bundled_runtime_state/.desktop-protected-activation" "$bundled_runtime_state/runne-daemon"
  echo "Runtime state reset: activation + daemon session cleared"
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
