#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
metadata="$repo_root/target/dev-linux-metadata"
manifest="$metadata/public-keys.json"
root_env="$metadata/update-root.env"
[[ $# == 0 ]] || { echo "usage: $0" >&2; exit 2; }
mkdir -p "$metadata"
[[ ! -e "$manifest" && ! -e "$root_env" ]] || {
  echo "error: keyset outputs already exist; refusing reinitialization" >&2
  exit 1
}
cd "$repo_root"
cargo build -p runne-update-metadata-producer --features dev-keyset-init
target/debug/runne-update-metadata-producer init-dev-keyset \
  --public-manifest "$manifest" --key-store secret-service
MANIFEST="$manifest" ROOT_ENV="$root_env" python3 <<'PY'
import json, os, re
manifest = json.load(open(os.environ["MANIFEST"], encoding="utf-8"))
mapping = {
    "RUNNE_UPDATE_ROOT_A_ID": "rootAId", "RUNNE_UPDATE_ROOT_A_HEX": "rootAHex",
    "RUNNE_UPDATE_ROOT_B_ID": "rootBId", "RUNNE_UPDATE_ROOT_B_HEX": "rootBHex",
    "RUNNE_UPDATE_ROOT_C_ID": "rootCId", "RUNNE_UPDATE_ROOT_C_HEX": "rootCHex",
    "RUNNE_UPDATE_SNAPSHOT_ID": "snapshotId", "RUNNE_UPDATE_SNAPSHOT_HEX": "snapshotHex",
    "RUNNE_UPDATE_TIMESTAMP_ID": "timestampId", "RUNNE_UPDATE_TIMESTAMP_HEX": "timestampHex",
}
with open(os.environ["ROOT_ENV"], "x", encoding="utf-8") as out:
    os.chmod(out.name, 0o600)
    for env, field in mapping.items():
        value = manifest[field]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise SystemExit("invalid public key manifest value")
        out.write(f"{env}={value}\n")
PY
chmod 600 "$manifest" "$root_env"
echo "Public development trust roots created; signing seeds remain in Secret Service."
