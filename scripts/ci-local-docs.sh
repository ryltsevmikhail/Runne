#!/usr/bin/bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
    exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

readonly trusted_python="${GOCODE_TRUSTED_PYTHON:?}"
"$trusted_python" scripts/validate-docs.py --strict
"$trusted_python" scripts/desktop/validate-docs.py --strict
