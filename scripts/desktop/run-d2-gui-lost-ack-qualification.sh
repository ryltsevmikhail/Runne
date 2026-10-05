#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 D2_GUI_BINARY RUNNED_BINARY" >&2
  exit 2
fi
app=$(realpath "$1")
daemon=$(realpath "$2")
base=$(git rev-parse --show-toplevel)
root=$(mktemp -d "${TMPDIR:-/tmp}/runne-d2-gui.XXXXXX")
chmod 700 "$root"
mkdir -m 700 "$root/runtime" "$root/data" "$root/config" "$root/markers"
mkdir -m 700 -p "$root/config/runne-daemon" "$root/runtime/runne-daemon"
sha256sum \
  "$app" "$daemon" "$base/apps/desktop/dist/index.html" \
  "$base/apps/desktop/src-tauri/src/gui_qualification.rs" \
  "$base/apps/desktop/src-tauri/src/gui_qualification_connect.rs" \
  "$base/apps/desktop/src-tauri/src/gui_qualification_page_script.rs" \
  "$base/apps/desktop/src-tauri/src/lib_parts/managed_task_run_commands.rs" \
  "$base/apps/desktop/src-tauri/src/lib_parts/managed_task_run_handler.rs" \
  "$base/apps/desktop/src-tauri/src/lib_parts/run.rs" \
  "$base/apps/desktop/src-tauri/src/lib_parts/runtime_connect.rs" \
  "$base/apps/desktop/src-tauri/src/lib_parts/setup_app.rs" \
  "$base/apps/desktop/src/features/task-composer/ui/TaskComposer.vue" \
  "$base/apps/desktop/src/features/task-composer/model/use-task-composer.ts" \
  "$base/apps/desktop/src/features/task-composer/model/task-composer-scope.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session-write.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session-verify.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session-reconcile.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session-cleanup.ts" \
  "$base/apps/desktop/src/features/task-composer/model/draft-session-contract.ts" \
  "$base/apps/desktop/src/features/task-composer/model/pending-run.ts" \
  "$base/apps/desktop/src/entities/task-run/api/managed-task-draft.ts" \
  "$base/apps/desktop/src/entities/task-run/api/managed-task-run.ts" \
  "$base/apps/desktop/src/shared/i18n/managed-workflows-en.ts" \
  "$base/apps/desktop/src/shared/i18n/managed-workflows-ru.ts" \
  "$base/crates/runne-app-core/src/lib_parts/task_run/managed_draft.rs" \
  "$base/crates/runne-app-core/src/lib_parts/task_run/managed.rs" \
  "$base/crates/runne-app-core/src/lib_parts/task_run/managed_types.rs" \
  "$base/crates/runne-app-core/src/lib_parts/task_run.rs" \
  "$base/crates/runne-local-store/src/lib.rs" \
  "$base/crates/runne-local-store/Cargo.toml" \
  "$base/crates/runne-local-store/src/protected_draft.rs" \
  "$base/crates/runne-local-store/src/protected_draft/schema.rs" \
  "$base/crates/runne-local-store/src/protected_draft/operations.rs" \
  "$base/crates/runne-local-store/src/protected_draft/crypto.rs" \
  "$base/crates/runne-local-store/src/protected_draft/types.rs" \
  "$base/crates/runne-app-core/src/test_support.rs" \
  "$base/crates/runne-secure-store/src/test_support/persistent_test_secure_store.rs" \
  "$base/crates/runne-secure-store/src/test_support/persistent_test_secure_store/codec.rs" \
  "$base/crates/runne-secure-store/src/test_support/persistent_test_secure_store_tests.rs" \
  "$0" >"$root/source-hashes.txt"
git -C "$base" rev-parse HEAD >"$root/source-revision.txt"
hyprctl -i 0 monitors -j >"$root/native-output.json"
: "${XDG_RUNTIME_DIR:?must be launched in the authenticated Hyprland session}"
: "${XDG_RUNTIME_DIR:?must be launched in the authenticated Hyprland session}"
if [[ -z "${WAYLAND_DISPLAY:-}" ]]; then
  WAYLAND_DISPLAY=$(hyprctl -j instances | jq -r '.[0].wl_socket // empty')
fi
: "${WAYLAND_DISPLAY:?Hyprland did not report its Wayland socket}"
wayland_source="$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
test -S "$wayland_source"
ln -s "$wayland_source" "$root/runtime/$WAYLAND_DISPLAY"
cat > "$root/config/runne-daemon/config.toml" <<CONFIG
schema_version = 2
db_path = "$root/runtime/runne-daemon/event-log.db"
http_bind = "127.0.0.1:3000"
replay_integrity_key_path = "$root/runtime/runne-daemon/replay-integrity.key"
CONFIG
chmod 700 "$root/config/runne-daemon" "$root/runtime/runne-daemon"
chmod 600 "$root/config/runne-daemon/config.toml"
if ss -ltnH 'sport = :3000' | grep -q .; then
  echo "port 3000 is occupied; refusing to attach to a non-fixture daemon" >&2
  exit 1
fi
export XDG_RUNTIME_DIR="$root/runtime" XDG_DATA_HOME="$root/data" XDG_CONFIG_HOME="$root/config"
export WAYLAND_DISPLAY
"$daemon" >"$root/daemon.log" 2>&1 & daemon_pid=$!
active_gui_pid=
current_phase=not-started
process_running() {
  local pid=$1 state
  kill -0 "$pid" 2>/dev/null || return 1
  state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
  [[ -n "$state" && "$state" != Z* ]]
}
stop_owned_process() {
  local pid=$1 signal=$2 name=$3
  process_running "$pid" || { wait "$pid" 2>/dev/null || true; return 0; }
  kill -"$signal" "$pid" 2>/dev/null || true
  for _ in $(seq 1 50); do
    process_running "$pid" || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    process_running "$pid" || { wait "$pid" 2>/dev/null || true; return 0; }
    sleep 0.1
  done
  echo "could not stop owned $name process $pid within 7 seconds" >&2
  return 1
}
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$active_gui_pid" ]]; then
    stop_owned_process "$active_gui_pid" TERM GUI || { [[ $status -ne 0 ]] || status=1; }
  fi
  stop_owned_process "$daemon_pid" INT daemon || { [[ $status -ne 0 ]] || status=1; }
  printf '{"exitStatus":%s,"phase":"%s"}\n' "$status" "$current_phase" >"$root/harness-exit.json"
  echo "fixture evidence: $root"
  exit "$status"
}
trap cleanup EXIT
for _ in $(seq 1 240); do
  kill -0 "$daemon_pid" 2>/dev/null || { echo "fixture daemon exited" >&2; exit 1; }
  if grep -q 'daemon ready' "$root/daemon.log"; then break; fi
  sleep 0.25
done
grep -q 'daemon ready' "$root/daemon.log" || { echo "owned fixture daemon did not report ready" >&2; exit 1; }
export RUNNE_D2_GUI_FIXTURE_ROOT="$root"
export RUNNE_D2_GUI_PROJECT_ID=018f2e3a-7000-7000-8000-000000000201
export RUNNE_D2_GUI_WORKSPACE_ID=018f2e3a-7000-7000-8000-000000000202

launch_gui() {
  local phase=$1
  current_phase=$phase
  cat >"$root/launch-$phase.sh" <<LAUNCH
#!/usr/bin/env bash
set -euo pipefail
export XDG_RUNTIME_DIR='$root/runtime'
export XDG_DATA_HOME='$root/data'
export XDG_CONFIG_HOME='$root/config'
export WAYLAND_DISPLAY='$WAYLAND_DISPLAY'
export RUNNE_D2_GUI_FIXTURE_ROOT='$root'
export RUNNE_D2_GUI_FIXTURE_PHASE='$phase'
export RUNNE_D2_GUI_PROJECT_ID='$RUNNE_D2_GUI_PROJECT_ID'
export RUNNE_D2_GUI_WORKSPACE_ID='$RUNNE_D2_GUI_WORKSPACE_ID'
exec '$app' --external-runtime
LAUNCH
  chmod 700 "$root/launch-$phase.sh"
  "$root/launch-$phase.sh" >"$root/gui-$phase.log" 2>&1 &
  active_gui_pid=$!
  echo "$active_gui_pid" >"$root/gui-$phase.pid"
  for _ in $(seq 1 240); do
    kill -0 "$(cat "$root/gui-$phase.pid")" 2>/dev/null && return 0
    sleep 0.25
  done
  echo "GUI process was not launched in phase $phase" >&2
  return 1
}
wait_marker() {
  local path=$1
  for _ in $(seq 1 240); do
    [[ -s "$root/markers/$path" ]] && return 0
    if [[ -n "$active_gui_pid" ]] && ! kill -0 "$active_gui_pid" 2>/dev/null; then
      echo "native GUI exited before marker $path" >&2
      tail -n 30 "$root/gui-${current_phase}.log" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "missing native GUI marker: $path" >&2
  return 1
}
launch_gui draft-save
wait_marker draft-saved.json
test "$(jq -r .draftMatches "$root/markers/draft-saved.json")" = true
test "$(jq -r .draftRevision "$root/markers/draft-saved.json")" -ge 1
test "$(jq -r .taskRunCount "$root/markers/draft-saved.json")" = 0
test "$(jq -r .startHandlerCalls "$root/markers/draft-saved.json")" = 0
grim "$root/markers/draft-saved-native-window.png"
stop_owned_process "$active_gui_pid" TERM GUI-draft-save
active_gui_pid=
launch_gui draft-reload
wait_marker draft-restored.json
test "$(jq -r .draftMatches "$root/markers/draft-restored.json")" = true
test "$(jq -r .restored "$root/markers/draft-restored.json")" = true
test "$(jq -r .draftRevision "$root/markers/draft-restored.json")" -ge 1
test "$(jq -r .taskRunCount "$root/markers/draft-restored.json")" = 0
test "$(jq -r .startHandlerCalls "$root/markers/draft-restored.json")" = 0
grim "$root/markers/draft-restored-native-window.png"
stop_owned_process "$active_gui_pid" TERM GUI-draft-reload
active_gui_pid=
launch_gui lost-ack
wait_marker accepted-lost-ack.json
sleep 2
grim "$root/markers/lost-ack-native-window.png"
stop_owned_process "$active_gui_pid" KILL GUI-lost-ack
active_gui_pid=
launch_gui recover
wait_marker recovered-current.json
cp "$root/markers/recovered-current.json" "$root/markers/recovered-before-fresh.json"
wait_marker recovered-current-rendered.json
test "$(jq -r .checkpoint "$root/markers/recovered-current-rendered.json")" = rendered-accepted-task-run
test "$(jq -r .status "$root/markers/recovered-current-rendered.json")" = accepted
test "$(jq -r .taskRunId "$root/markers/recovered-current-rendered.json")" = "$(jq -r .taskRunId "$root/markers/recovered-before-fresh.json")"
stop_owned_process "$active_gui_pid" TERM GUI-recover
active_gui_pid=
launch_gui fresh
wait_marker accepted-fresh.json
wait_marker recovered-original.json
first=$(jq -r .taskRunId "$root/markers/accepted-lost-ack.json")
recovered=$(jq -r .taskRunId "$root/markers/recovered-before-fresh.json")
fresh=$(jq -r .taskRunId "$root/markers/accepted-fresh.json")
old_replay=$(jq -r .taskRunId "$root/markers/recovered-original.json")
[[ "$first" == "$recovered" && "$first" == "$old_replay" && "$fresh" != "$first" ]] || {
  echo "task identity assertions failed" >&2; exit 1;
}
test "$(jq -r .taskRunCount "$root/markers/accepted-lost-ack.json")" = 1
test "$(jq -r .taskRunCount "$root/markers/recovered-before-fresh.json")" = 1
test "$(jq -r .taskRunCount "$root/markers/accepted-fresh.json")" = 2
test "$(jq -r .taskRunCount "$root/markers/recovered-original.json")" = 2
test "$(jq -r .startHandlerCalls "$root/markers/accepted-lost-ack.json")" = 1
test "$(jq -r .startHandlerCalls "$root/markers/recovered-before-fresh.json")" = 1
test "$(jq -r .startHandlerCalls "$root/markers/accepted-fresh.json")" = 2
test "$(jq -r .startHandlerCalls "$root/markers/recovered-original.json")" = 2
stop_owned_process "$active_gui_pid" TERM GUI-fresh
active_gui_pid=
jq -n --arg app "$(basename "$app")" --arg daemon "$(basename "$daemon")" \
  --arg first "$first" --arg fresh "$fresh" --arg old_replay "$old_replay" \
  '{result:"PASS",scope:"native Tauri/WebView + real local daemon; fixture SecureStore; no provider call qualification",app:$app,daemon:$daemon,secure_store:"persistent deterministic test fixture",provider:"no external/paid provider call",draft_saved:true,draft_restored:true,first_task_run:$first,fresh_task_run:$fresh,old_token_replay:$old_replay}' \
  >"$root/qualification-result.json"
echo "PASS: $root/qualification-result.json"
