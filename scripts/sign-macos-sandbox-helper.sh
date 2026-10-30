#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Sign the macOS sandbox helper.

Usage:
  scripts/sign-macos-sandbox-helper.sh [--identity NAME] [--ad-hoc] BINARY

Options:
  --identity NAME   Developer ID Application identity.
  --ad-hoc          Ad-hoc sign for local testing only.
  -h, --help        Show this help.

Environment:
  RUNNE_MACOS_SIGNING_IDENTITY  Override the default signing identity.

The helper applies an explicit Seatbelt profile with sandbox_init; it must not
carry com.apple.security.app-sandbox or com.apple.security.inherit.
USAGE
}

identity="${RUNNE_MACOS_SIGNING_IDENTITY:-}"
ad_hoc=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity)
      [[ $# -ge 2 ]] || { echo "error: --identity requires a value" >&2; exit 2; }
      identity="$2"
      shift 2
      ;;
    --ad-hoc)
      ad_hoc=1
      shift
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

[[ $# -eq 1 ]] || { echo "error: expected exactly one binary path" >&2; usage >&2; exit 2; }
binary="$1"
[[ -f "$binary" ]] || { echo "error: binary not found: $binary" >&2; exit 1; }
[[ "$(basename "$binary")" == "runne-sandbox-helper" ]] || {
  echo "error: refusing to sign a binary that is not runne-sandbox-helper" >&2
  exit 1
}

if [[ -z "$identity" && $ad_hoc -eq 0 ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk '/Developer ID Application/ { print $2; exit }')
fi

if [[ -n "$identity" ]]; then
  security find-identity -v -p codesigning 2>/dev/null | grep -q "$identity" || {
    echo "error: requested signing identity not found: $identity" >&2
    exit 1
  }
  codesign --sign "$identity" --force --options runtime --timestamp "$binary"
elif [[ $ad_hoc -eq 1 ]]; then
  echo "warning: ad-hoc signature is for local testing only" >&2
  codesign --sign - --force --options runtime "$binary"
else
  echo "error: no valid Developer ID Application identity found" >&2
  echo "Set RUNNE_MACOS_SIGNING_IDENTITY, import a Developer ID certificate, or pass --ad-hoc." >&2
  exit 1
fi

codesign --verify --strict --verbose=2 "$binary"
echo "Signed: $binary"
