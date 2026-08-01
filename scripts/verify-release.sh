#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s --candidate <directory> [--fixture-only]\n' "$0" >&2
    exit 2
}

FIXTURE_ONLY=0
if [ "$#" -eq 3 ] && [ "$1" = '--fixture-only' ]; then
    FIXTURE_ONLY=1
    shift
fi
[ "$#" -eq 2 ] && [ "$1" = '--candidate' ] || usage
[ -d "$2" ] || { printf 'ERROR: candidate directory is required\n' >&2; exit 2; }
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { printf 'ERROR: must run inside a Git worktree\n' >&2; exit 2; }
SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse --verify HEAD^{commit} 2>/dev/null) || { printf 'ERROR: source HEAD is required\n' >&2; exit 2; }
if git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet; then SOURCE_CLEAN=1; else SOURCE_CLEAN=0; fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$SCRIPT_DIR/verify_release.py" "$REPO_ROOT" "$SOURCE_REVISION" "$SOURCE_CLEAN" "$2" "$FIXTURE_ONLY"
