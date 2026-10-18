#!/usr/bin/env bash
set -euo pipefail

evidence="docs/evidence/CANONICAL_TASKRUN_DAEMON_EVIDENCE.md"
test -f "$evidence"

for forbidden_router in \
  "merge(command_router" \
  "merge(query_router"
do
  if grep -n -F "$forbidden_router" crates/runne-http/src/router_parts/production.rs; then
    echo "synthetic legacy router is mounted in the production surface" >&2
    exit 1
  fi
done

if ! grep -q -F ".merge(replay_router(replay_state))" crates/runne-http/src/router_parts/production.rs; then
  echo "canonical replay router is absent from the production surface" >&2
  exit 1
fi

cargo test -p runne-api --test task_run_contract --locked
cargo test -p runne-runtime --test task_run_host --locked
cargo test -p runne-http --all-targets --locked
cargo test -p runne-daemon --all-targets --locked
cargo test -p runne-runtime-client --all-targets --locked
# The runne-cli real-process protected-runtime tests copy target/debug/runned
# into their owner-private fixture and launch it as the protected daemon. The
# default-features builds above leave a runned binary without the protected
# activation channel, which exits before reading stdin (surfacing as
# ProtectedChannelUnavailable at launch_request_write), so stage the exact
# daemon build those tests require immediately before running them.
cargo build -p runne-daemon --bin runned --locked --features desktop-protected
cargo test -p runne-cli --all-targets --locked
cargo test -p runne-app-core --all-targets --features test-support --locked
node scripts/desktop/stage_bundled_daemon.mjs
node scripts/desktop/stage_bundled_cli.mjs
cargo test -p runne-desktop --all-targets --locked
git diff --check
