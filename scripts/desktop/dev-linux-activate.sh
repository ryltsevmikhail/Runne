#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
profile="${1:-}"
if [[ ! "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo "usage: $0 PROFILE" >&2
  exit 2
fi
profile_dir="$repo_root/target/dev-linux-profiles/$profile"
version="$(python3 -c 'import json; print(json.load(open("apps/desktop/src-tauri/tauri.conf.json"))["version"])')"
app_image="$profile_dir/artifacts/Runne-$version-x86_64.AppImage"
if [[ ! -x "$app_image" || ! -d "$profile_dir/data" ]]; then
  echo "activation profile is not installed" >&2
  exit 2
fi
if pgrep -u "$(id -u)" -x runne-desktop >/dev/null; then
  echo "close the existing desktop instance before activation" >&2
  exit 2
fi
export XDG_DATA_HOME="$profile_dir/data"
activation_record="$XDG_DATA_HOME/com.runne.desktop/bundled-runtime/linux-enrollment-activation.json"
if [[ -e "$activation_record" || -L "$activation_record" ]]; then
  echo "activation record already exists" >&2
  exit 2
fi
output_file="$(mktemp)"
trap 'rm -f -- "$output_file"' EXIT
set +e
"$app_image" --approve-linux-enrollment=catalog >"$output_file" 2>&1
app_status="$?"
set -e
if [[ "$app_status" -ne 0 ]] || ! grep -Fxq 'linux-enrollment-approval:published' "$output_file"; then
  echo "native activation did not complete" >&2
  exit 1
fi
if [[ ! -f "$activation_record" || "$(stat -c '%a' -- "$activation_record")" != 600 ]]; then
  echo "activation record was not safely published" >&2
  exit 1
fi
