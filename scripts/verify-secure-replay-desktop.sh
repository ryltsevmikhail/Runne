#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

usage() {
    echo "expected exactly one mode: runtime, frontend or all" >&2
    exit 2
}

run_runtime() {
    cargo run -p gocode-runtime --bin generate-ui-contract --locked -- --check
    python3 scripts/verify_secure_replay_evidence.py \
        docs/evidence/secure-replay-desktop-resume-v1.json
    cargo test -p gocode-daemon --test desktop_replay_resume_e2e --locked
}

run_frontend() {
    pnpm --filter @gocode/desktop test
    pnpm typecheck
    pnpm exec playwright test tests/desktop/e2e/replay-resume.spec.ts
    python3 scripts/desktop/validate_architecture.py
    pnpm validate:docs
}

if [ "$#" -ne 1 ]; then
    usage
fi

case "$1" in
    runtime)
        run_runtime
        ;;
    frontend)
        run_frontend
        ;;
    all)
        run_runtime
        run_frontend
        git diff --check
        ;;
    *)
        usage
        ;;
esac
