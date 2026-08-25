#!/usr/bin/env bash
set -euo pipefail

package_path=${1:?package path is required}
evidence_path=${2:?evidence path is required}
platform_pair=${NATIVE_PLATFORM_PAIR:-ubuntu-22.04-x86_64}

export NATIVE_PROBE_PACKAGE="$package_path"
export NATIVE_PROBE_EVIDENCE="$evidence_path"
export NATIVE_PROBE_PLATFORM="$platform_pair"

if ! command -v xvfb-run >/dev/null || ! command -v dbus-run-session >/dev/null; then
  echo "BLOCKED: Linux packaged probe requires Xvfb and D-Bus" >&2
  exit 1
fi

exec xvfb-run --auto-servernum --server-args="-screen 0 1440x900x24" \
  dbus-run-session -- bash -c '
    set -euo pipefail
    eval "$(gnome-keyring-daemon --start --components=secrets)"
    export GNOME_KEYRING_CONTROL GNOME_KEYRING_PID
    cd "$SOURCECRAFT_WORKSPACE"
    python3 scripts/desktop/native_package_probe.py preflight \
      --platform-pair "$NATIVE_PROBE_PLATFORM" --package "$NATIVE_PROBE_PACKAGE"
    python3 scripts/desktop/native_package_probe.py run \
      --platform-pair "$NATIVE_PROBE_PLATFORM" \
      --package "$NATIVE_PROBE_PACKAGE" \
      --evidence "$NATIVE_PROBE_EVIDENCE" \
      --runner-identity "$SOURCECRAFT_NATIVE_RUNNER_IDENTITY_PATH" \
      --trust-root "$SOURCECRAFT_NATIVE_RUNNER_TRUST_ROOT_PATH" \
      --trust-root-sha256 "$SOURCECRAFT_NATIVE_RUNNER_TRUST_ROOT_SHA256" \
      --job-id "$SOURCECRAFT_TASK" \
      --workflow-run-id "$SOURCECRAFT_RUN_ID"
  '
