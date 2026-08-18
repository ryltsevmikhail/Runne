#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Notarize and staple a signed macOS archive (.zip, .dmg, or .pkg).

Prerequisites:
  1. The binary/archive must already be signed with Developer ID.
  2. notarytool credentials must be stored in the keychain:
       xcrun notarytool store-credentials \
         --apple-id "you@example.com" \
         --team-id "758F9Z45SR" \
         --password <app-specific-password> \
         GOCODE_NOTARY

Usage:
  scripts/notarize-macos-binary.sh [--profile NAME] ARCHIVE

Options:
  --profile NAME  notarytool keychain profile name (default: GOCODE_NOTARY)
  -h, --help      Show this help

Environment:
  GOCODE_NOTARY_PROFILE  Override default notarytool keychain profile.

Example:
  scripts/notarize-macos-binary.sh gocode-runtime-0.1.0-aarch64-apple-darwin.zip
USAGE
}

profile="${GOCODE_NOTARY_PROFILE:-GOCODE_NOTARY}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "error: --profile requires a value" >&2
        exit 2
      fi
      profile="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  echo "error: expected exactly one archive path" >&2
  usage >&2
  exit 2
fi

archive="$1"

if [[ ! -f "$archive" ]]; then
  echo "error: archive not found: $archive" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: notarization must run on macOS" >&2
  exit 1
fi

submission_id=$(xcrun notarytool submit "$archive" --keychain-profile "$profile" --wait --output-format json 2>&1 \
  | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('id', d.get('submissionId', '')))")

if [[ -z "$submission_id" ]]; then
  echo "error: failed to submit archive for notarization" >&2
  exit 1
fi

xcrun notarytool log "$submission_id" --keychain-profile "$profile" 2>&1 | head -50
xcrun stapler staple "$archive"
xcrun stapler validate "$archive"
echo "Notarized and stapled: $archive"
