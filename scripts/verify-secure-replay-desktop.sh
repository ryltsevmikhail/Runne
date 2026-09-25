#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

usage() {
    echo "expected exactly one mode: runtime, frontend or all" >&2
    exit 2
}

run_runtime() {
    cargo run -p runne-runtime --bin generate-ui-contract --locked -- --check
    python3 scripts/verify_secure_replay_evidence.py \
        --manifest docs/evidence/secure-replay-desktop-resume-v1.json \
        --legacy-blob 4713d84e94f68ae9c29de71325d4ecbd8d3096bb
    python3 scripts/verify_secure_replay_evidence.py \
        --manifest docs/evidence/secure-replay-desktop-resume-v2.json \
        --base d4dbabff8272118d99e6388dfbbf6df48b22faae \
        --head 6030bdbe77a3cd5dbcaeaa3bfd2d7bc3a5b4d3ca \
        --schema docs/schemas/secure-replay-evidence-v2.schema.json
    cargo test -p runne-daemon --test desktop_replay_resume_e2e --locked
}

run_frontend() {
    run_pnpm --filter @runne/desktop test
    run_pnpm --filter @runne/desktop typecheck
    run_pnpm --filter @runne/product typecheck
    run_pnpm exec playwright test tests/desktop/e2e/replay-resume.spec.ts
    python3 scripts/desktop/validate_architecture.py
}

run_pnpm() {
    if [ -n "${RUNNE_TRUSTED_NODE:-}" ] && [ -n "${RUNNE_TRUSTED_PNPM:-}" ]; then
        trusted_node_dir="$(dirname -- "$RUNNE_TRUSTED_NODE")"
        trusted_pnpm_dir="$(dirname -- "$RUNNE_TRUSTED_PNPM")"
        PATH="$trusted_pnpm_dir:$trusted_node_dir:$PATH" \
            "$RUNNE_TRUSTED_NODE" "$RUNNE_TRUSTED_PNPM" "$@"
    else
        pnpm "$@"
    fi
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
