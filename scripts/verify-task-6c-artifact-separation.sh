#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
normal_target=$(mktemp -d)
features_target=$(mktemp -d)
normal_messages=$(mktemp)
features_messages=$(mktemp)

CARGO_TARGET_DIR="$normal_target" cargo build -p gocode-daemon --bin gocode-daemon --release --locked \
    --message-format=json-render-diagnostics > "$normal_messages"
CARGO_TARGET_DIR="$features_target" cargo build -p gocode-daemon --bin gocode-daemon --release --all-features --locked \
    --message-format=json-render-diagnostics > "$features_messages"

python3 "$root/scripts/verify-task-6c-artifact-json.py" --messages "$normal_messages" --target-dir "$normal_target"
python3 "$root/scripts/verify-task-6c-artifact-json.py" --messages "$features_messages" --target-dir "$features_target"

for artifact in "$normal_target/release/gocode-daemon" "$features_target/release/gocode-daemon"; do
    [ -f "$artifact" ] || { printf 'missing daemon artifact: %s\n' "$artifact" >&2; exit 1; }
    if strings "$artifact" | grep -Eq 'gocode-daemon-loopback-fixture|activation_process|recovery_process'; then
        printf 'fixture marker leaked into daemon artifact: %s\n' "$artifact" >&2
        exit 1
    fi
done

python3 "$root/scripts/verify-task-6c-internal-deps.py"
if rg -n 'GOCODE_TEST_OPENAI_ROUTE|GOCODE_TEST_OPENAI_CA_DER|TestOpenAiRoute' "$root/crates/gocode-daemon"; then
    printf 'synthetic daemon marker found\n' >&2
    exit 1
fi
printf 'Task 6C normal/all-features artifact separation passed.\n'
