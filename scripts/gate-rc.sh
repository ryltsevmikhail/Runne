#!/usr/bin/env bash
# rc-honest gate wrapper: full per-run log + real exit code file + provenance,
# prints a short tail of the log (a successful `tail` must never mask the
# child's exit status) and exits with the CHILD's exit code.
#
# Usage: scripts/gate-rc.sh <name> -- <command...>
# Env:   RUNNE_GATE_LOG_DIR (default: <repo>/target/gate-logs)
#        RUNNE_GATE_REPO    (default: wrapper's repo root; used for provenance)
# Self-test (negative+positive rc control): scripts/gate-rc.sh --self-test
set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
LOG_DIR="${RUNNE_GATE_LOG_DIR:-$REPO_ROOT/target/gate-logs}"
REPO="${RUNNE_GATE_REPO:-$REPO_ROOT}"
mkdir -p "$LOG_DIR"

self_test() {
    local fail=0
    "$0" self-test-neg -- bash -c 'echo child-out; exit 7'
    local neg=$?
    "$0" self-test-pos -- bash -c 'echo child-ok'
    local pos=$?
    # The negative control must prove the wrapper PROCESS exits 7 even though
    # the in-wrapper `tail` of the log succeeds.
    if [ "$neg" -eq 7 ] && [ "$pos" -eq 0 ]; then
        echo "SELF-TEST PASS: child exit 7 -> wrapper exit $neg; child exit 0 -> wrapper exit $pos"
        return 0
    fi
    echo "SELF-TEST FAIL: neg=$neg (want 7), pos=$pos (want 0)" >&2
    return 1
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
fi

if [ $# -lt 3 ] || [ "$2" != "--" ]; then
    echo "Usage: $0 <name> -- <command...> | --self-test" >&2
    exit 2
fi

NAME=$1
shift 2
LOG="$LOG_DIR/${NAME}.log"
RCF="${LOG}.rc"
PROV="${LOG}.provenance.txt"
{
    echo "COMMAND: $*"
    echo "DATE: $(date -Is)"
    echo "REPO_SHA: $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "DIRTY_ENTRIES: $(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)"
    echo "TOOLCHAIN: $(rustc --version 2>/dev/null || echo no-rustc); $(node --version 2>/dev/null || echo no-node)"
} > "$PROV"

"$@" > "$LOG" 2>&1
RC=$?
echo "$RC" > "$RCF"
# Successful `tail` after a failing child must NOT mask the child's rc.
tail -n 5 "$LOG" || true
echo "GATE[$NAME] rc=$RC log=$LOG rcfile=$RCF"
exit "$RC"
