#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Sign a single macOS binary with Developer ID Application identity.

Usage:
  scripts/sign-macos-binary.sh [--identity NAME] BINARY

Options:
  --identity NAME  Signing identity (default: first valid Developer ID Application)
  -h, --help       Show this help

Environment:
  RUNNE_MACOS_SIGNING_IDENTITY  Override default signing identity.

Example:
  scripts/sign-macos-binary.sh target/release/gocode-daemon
USAGE
}

identity="${RUNNE_MACOS_SIGNING_IDENTITY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity)
      if [[ $# -lt 2 ]]; then
        echo "error: --identity requires a value" >&2
        exit 2
      fi
      identity="$2"
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
  echo "error: expected exactly one binary path" >&2
  usage >&2
  exit 2
fi

binary="$1"

if [[ ! -f "$binary" ]]; then
  echo "error: binary not found: $binary" >&2
  exit 1
fi

if [[ -z "$identity" ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk '/Developer ID Application/ { print $2; exit }')
  if [[ -z "$identity" ]]; then
    echo "error: no valid Developer ID Application identity found" >&2
    echo "Set RUNNE_MACOS_SIGNING_IDENTITY or import a Developer ID certificate into keychain." >&2
    exit 1
  fi
fi

# Verify the identity exists before mutating the binary.
if ! security find-identity -v -p codesigning 2>/dev/null | grep -q "${identity}"; then
  echo "error: requested signing identity not found: $identity" >&2
  exit 1
fi

codesign \
  --sign "$identity" \
  --force \
  --options runtime \
  --timestamp \
  "$binary"

codesign --verify --verbose "$binary"
echo "Signed: $binary"
