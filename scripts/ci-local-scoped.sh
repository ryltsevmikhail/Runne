#!/usr/bin/bash
set -euo pipefail
# Path-filtered local gate: runs only the gates relevant to changed paths.
# The canonical receipt gate stays `pnpm ci:local`.
# Usage: bash scripts/ci-local-scoped.sh [--base REF] [--gates LIST] [--full] [--dry-run]
export PATH="/usr/bin:/bin"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
exec /usr/bin/python3 -m scripts.ci_local_scope "$@"
