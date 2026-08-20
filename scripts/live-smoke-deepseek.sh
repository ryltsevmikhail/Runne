#!/usr/bin/env bash
# Runne live DeepSeek smoke: a real provider canary through daemon + CLI.
#
# Refuses to run without a configured deepseek credential and without the
# RUNNE_LIVE_SMOKE=1 opt-in (a real call may spend money). Never prints
# credential material; with RUNNE_LIVE_SMOKE_KEY it additionally scans every
# captured output byte-for-byte and fails if the value leaks.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/live-smoke-deepseek.sh [--bin-dir DIR] [--no-daemon]

Options:
  --bin-dir DIR   Directory containing runne and runned (default: PATH)
  --no-daemon     Assume a running daemon; do not start/stop one
  -h, --help      Show this help

Environment:
  RUNNE_LIVE_SMOKE=1     Required: authorizes a real paid DeepSeek call.
  RUNNE_LIVE_SMOKE_KEY   Optional: exact credential value, used ONLY for the
                          output redaction scan; never printed.

Exit codes:
  0  all checks passed
  1  runtime or live call failure
  2  usage error or missing RUNNE_LIVE_SMOKE=1 opt-in
  3  active provider is not deepseek (no-silent-fallback refusal)
  4  deepseek credential not configured
USAGE
}

bin_dir=""
manage_daemon=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      if [[ $# -lt 2 ]]; then
        echo "error: --bin-dir requires a directory" >&2
        exit 2
      fi
      bin_dir="$2"
      shift 2
      ;;
    --no-daemon)
      manage_daemon=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${RUNNE_LIVE_SMOKE:-}" != "1" ]]; then
  echo "refusing: this smoke makes a real paid DeepSeek request." >&2
  echo "set RUNNE_LIVE_SMOKE=1 to authorize it." >&2
  exit 2
fi

resolve_binary() {
  local name="$1"
  if [[ -n "$bin_dir" ]]; then
    [[ -x "$bin_dir/$name" ]] || {
      echo "error: missing executable: $bin_dir/$name" >&2
      exit 2
    }
    echo "$bin_dir/$name"
  else
    command -v "$name" || {
      echo "error: $name not found in PATH (use --bin-dir)" >&2
      exit 2
    }
  fi
}

GCODE="$(resolve_binary runne)"
GDAEMON="$(resolve_binary runned)"

SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/runne-live-smoke.XXXXXX")"
chmod 700 "$SMOKE_DIR"
SMOKE_LOG="$SMOKE_DIR/smoke.log"
DAEMON_LOG="$SMOKE_DIR/daemon.log"
DAEMON_PID=""
STARTED_DAEMON=0

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

# Runs one labelled check, streaming its output to the terminal and appending
# it to the capture log for the redaction scan. pipefail preserves exit codes.
run_checked() {
  local label="$1"
  shift
  echo "--- $label ---"
  "$@" 2>&1 | tee -a "$SMOKE_LOG"
}

echo "smoke dir: $SMOKE_DIR"

# 1. Credential pre-flight: refuses without a configured deepseek credential.
#    `|| true` keeps the refusal message on non-zero pre-flight exits.
CREDENTIAL_STATUS="$(run_checked "deepseek credential status" \
  "$GCODE" provider credential status --provider deepseek || true)"
if [[ "$CREDENTIAL_STATUS" != "configured" ]]; then
  echo "refusing: deepseek credential is not configured." >&2
  echo "run: runne provider credential set --provider deepseek --stdin" >&2
  exit 4
fi

# 2. Provider-selection pre-flight: refuse if the active provider is not
#    deepseek. This is the no-silent-fallback assertion.
DOCTOR_OUTPUT="$(run_checked "daemon doctor" "$GDAEMON" doctor || true)"
if ! grep -q "active provider: deepseek_responses_text_v1" <<<"$DOCTOR_OUTPUT"; then
  echo "refusing: active provider is not deepseek (no silent fallback)." >&2
  echo "provider selection lives in the owner-private daemon config;" >&2
  echo "run 'runned doctor' to see the current selection." >&2
  exit 3
fi
if ! grep -q "credential deepseek: configured" <<<"$DOCTOR_OUTPUT"; then
  echo "refusing: daemon sees deepseek credential as not configured." >&2
  exit 4
fi

# 3. Daemon lifecycle: reuse a healthy daemon, otherwise start one and stop it
#    on exit.
if [[ "$manage_daemon" == "1" ]] && "$GCODE" health >/dev/null 2>&1; then
  echo "note: a healthy daemon is already running; reusing it."
  echo "note: redaction scan covers CLI output only in this mode."
  manage_daemon=0
fi
if [[ "$manage_daemon" == "1" ]]; then
  "$GDAEMON" >"$DAEMON_LOG" 2>&1 &
  DAEMON_PID=$!
  STARTED_DAEMON=1
  HEALTHY=0
  for _ in $(seq 1 30); do
    if "$GCODE" health >/dev/null 2>&1; then
      HEALTHY=1
      break
    fi
    sleep 1
  done
  if [[ "$HEALTHY" != "1" ]]; then
    echo "error: daemon did not become healthy in time." >&2
    tail -n 20 "$DAEMON_LOG" >&2 || true
    exit 1
  fi
fi

run_checked "runtime health" "$GCODE" health
run_checked "runtime status" "$GCODE" status

# 4. Live conversation: create, send one message through the real DeepSeek
#    endpoint, then replay the messages list.
WORKSPACE_ID="$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null \
  || uuidgen 2>/dev/null | tr 'A-Z' 'a-z')"
if [[ -z "$WORKSPACE_ID" ]]; then
  echo "error: cannot generate a workspace UUID" >&2
  exit 1
fi

CONVERSATION_ID="$(run_checked "conversation create" \
  "$GCODE" conversation create --workspace-id "$WORKSPACE_ID" | tail -n 1)"
if [[ -z "$CONVERSATION_ID" ]]; then
  echo "error: conversation create returned no id" >&2
  exit 1
fi

REPLY="$(run_checked "conversation send (live deepseek)" \
  "$GCODE" conversation send \
  --conversation-id "$CONVERSATION_ID" \
  --expected-version 1 \
  --text "Reply with exactly: RUNNE-SMOKE-OK")"
if [[ -z "${REPLY//[[:space:]]/}" ]]; then
  echo "error: empty assistant response" >&2
  exit 1
fi

REPLAY_OUTPUT="$(run_checked "conversation messages (replay)" \
  "$GCODE" conversation messages --conversation-id "$CONVERSATION_ID")"
if ! grep -q -F "$(printf '%s' "$REPLY" | head -c 20)" <<<"$REPLAY_OUTPUT"; then
  echo "error: replay does not contain the assistant response" >&2
  exit 1
fi

# 5. Redaction scan: the exact credential value must not appear anywhere in
#    the captured output. The value itself is never printed.
if [[ -n "${RUNNE_LIVE_SMOKE_KEY:-}" ]]; then
  if grep -q -F -- "$RUNNE_LIVE_SMOKE_KEY" "$SMOKE_LOG" "$DAEMON_LOG" 2>/dev/null; then
    echo "error: REDACTION FAILURE: credential value found in captured output" >&2
    exit 1
  fi
  echo "--- redaction scan: passed (credential value absent from output) ---"
else
  echo "note: RUNNE_LIVE_SMOKE_KEY not set; byte-level redaction scan skipped."
fi

# 6. Shutdown of the daemon we started.
if [[ "$STARTED_DAEMON" == "1" ]]; then
  kill "$DAEMON_PID"
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
fi

echo
echo "PASS: live DeepSeek smoke completed."
echo "  verified: credential configured, active provider deepseek, daemon healthy,"
echo "  live response non-empty, replay contains the response, redaction scan."
echo "  not verified here: usage/accounting (not yet exposed via CLI)."
