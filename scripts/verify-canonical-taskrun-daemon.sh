#!/usr/bin/env bash
set -euo pipefail

evidence="docs/evidence/CANONICAL_TASKRUN_DAEMON_EVIDENCE.md"
test -f "$evidence"

for forbidden_router in \
  "merge(command_router" \
  "merge(query_router"
do
  if grep -n -F "$forbidden_router" crates/gocode-http/src/router_parts/production.rs; then
    echo "synthetic legacy router is mounted in the production surface" >&2
    exit 1
  fi
done

if ! grep -q -F ".merge(replay_router(replay_state))" crates/gocode-http/src/router_parts/production.rs; then
  echo "canonical replay router is absent from the production surface" >&2
  exit 1
fi

cargo test -p gocode-api --test task_run_contract --locked
cargo test -p gocode-runtime --test task_run_host --locked
cargo test -p gocode-http --all-targets --locked
cargo test -p gocode-daemon --all-targets --locked
cargo test -p gocode-runtime-client --all-targets --locked
cargo test -p gocode-cli --all-targets --locked
cargo test -p gocode-app-core --all-targets --locked
cargo test -p gocode-desktop --all-targets --locked
python3 scripts/validate-docs.py --strict
git diff --check
