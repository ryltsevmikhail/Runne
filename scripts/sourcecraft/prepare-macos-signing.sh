#!/usr/bin/env bash
set -euo pipefail
umask 077

# Source this file inside one protected macOS build task. It intentionally
# exports only opaque build variables and keeps the imported certificate in a
# temporary keychain owned by this task.

: "${APPLE_CERTIFICATE:?APPLE_CERTIFICATE is required}"
: "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD is required}"
: "${APPLE_ID:?APPLE_ID is required}"
: "${APPLE_PASSWORD:?APPLE_PASSWORD is required}"
: "${APPLE_SIGNING_FINGERPRINT:?APPLE_SIGNING_FINGERPRINT is required}"
: "${APPLE_SIGNING_IDENTITY:?APPLE_SIGNING_IDENTITY is required}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required}"

SIGNING_TEMP_DIR="$(mktemp -d)"
SIGNING_KEYCHAIN="$SIGNING_TEMP_DIR/runne-signing.keychain-db"
SIGNING_CERTIFICATE="$SIGNING_TEMP_DIR/runne-signing.p12"
SIGNING_KEYCHAIN_PASSWORD="$(openssl rand -base64 32)"
SIGNING_PREVIOUS_KEYCHAINS="$(security list-keychains -d user | tr -d '"' | tr '\n' ' ')"
SIGNING_PREVIOUS_DEFAULT="$(security default-keychain -d user | tr -d '"')"

cleanup_macos_signing() {
  security list-keychains -d user -s $SIGNING_PREVIOUS_KEYCHAINS >/dev/null 2>&1 || true
  if [ -n "$SIGNING_PREVIOUS_DEFAULT" ]; then
    security default-keychain -d user -s "$SIGNING_PREVIOUS_DEFAULT" >/dev/null 2>&1 || true
  fi
  security delete-keychain "$SIGNING_KEYCHAIN" >/dev/null 2>&1 || true
  rm -rf "$SIGNING_TEMP_DIR"
}
trap cleanup_macos_signing EXIT

printf '%s' "$APPLE_CERTIFICATE" | base64 -D > "$SIGNING_CERTIFICATE"
security create-keychain -p "$SIGNING_KEYCHAIN_PASSWORD" "$SIGNING_KEYCHAIN" >/dev/null
security set-keychain-settings -lut 1800 "$SIGNING_KEYCHAIN"
security unlock-keychain -p "$SIGNING_KEYCHAIN_PASSWORD" "$SIGNING_KEYCHAIN"
security import "$SIGNING_CERTIFICATE" -k "$SIGNING_KEYCHAIN" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$SIGNING_KEYCHAIN_PASSWORD" "$SIGNING_KEYCHAIN" >/dev/null
security list-keychains -d user -s "$SIGNING_KEYCHAIN" $SIGNING_PREVIOUS_KEYCHAINS >/dev/null
security default-keychain -d user -s "$SIGNING_KEYCHAIN" >/dev/null

identity_output="$(security find-identity -v -p codesigning "$SIGNING_KEYCHAIN")"
printf '%s\n' "$identity_output" | grep -F "\"$APPLE_SIGNING_IDENTITY\"" >/dev/null
security find-certificate -c "$APPLE_SIGNING_IDENTITY" -p "$SIGNING_KEYCHAIN" > "$SIGNING_TEMP_DIR/runne-signing.pem"
actual_fingerprint="$(openssl x509 -in "$SIGNING_TEMP_DIR/runne-signing.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')"
test "$(printf '%s' "$actual_fingerprint" | tr '[:lower:]' '[:upper:]')" = "$(printf '%s' "$APPLE_SIGNING_FINGERPRINT" | tr '[:lower:]' '[:upper:]')"

export APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID
