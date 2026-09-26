#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { echo "error: $*" >&2; exit 1; }
require_clean_source() {
  git diff --quiet HEAD -- || fail "source tree has tracked changes; commit before qualification"
  [[ -z "$(git status --porcelain --untracked-files=all)" ]] \
    || fail "source tree has untracked files; commit or remove them before qualification"
}
[[ $# == 2 && "$1" == "qualify" && "${RUNNE_FINALIZE_QUALIFICATION:-}" == "1" ]] || {
  echo "error: qualification receipt generation is run by dev-linux-signed-workflow.sh finalize" >&2
  exit 2
}
profile="$2"
[[ "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "invalid profile name"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
[[ "$(uname -s):$(uname -m)" == "Linux:x86_64" ]] || fail "requires Linux x86_64"
require_clean_source
source_commit="$(git rev-parse --verify HEAD^{commit})"
version="$(python3 -c 'import json; print(json.load(open("apps/desktop/src-tauri/tauri.conf.json"))["version"])')"
app_out="$repo_root/target/dev-linux-profiles/$profile/artifacts"
app_dir="$app_out/Runne.AppDir"
appimage="$app_out/Runne-$version-x86_64.AppImage"
receipt="$app_out/qualification-v1.json"
log="$app_out/qualification-v1.log"
target_json="$repo_root/target/dev-linux-profiles/$profile/target.json"
[[ -d "$app_dir" && -f "$appimage" ]] || fail "run build for this profile first"
[[ -f "$target_json" ]] || fail "profile target policy is missing"
[[ "$(cat "$repo_root/target/dev-linux-profiles/$profile/source-commit.txt")" == "$source_commit" ]] \
  || fail "source commit changed since the AppImage build"
[[ ! -e "$receipt" && ! -L "$receipt" && ! -e "$log" && ! -L "$log" ]] \
  || fail "qualification receipt or log already exists"

extract_dir="$(mktemp -d "$app_out/.qualification-extract.XXXXXX")"
cleanup() { rm -rf -- "$extract_dir"; }
trap cleanup EXIT
test_command="cargo test -p runne-platform-desktop --lib"
component_command="AppImage extraction and required-component cmp checks"
printf '$ %s\n' "$test_command" >"$log"
if cargo test -p runne-platform-desktop --lib >>"$log" 2>&1; then
  test_status=0
else
  test_status=$?
fi

printf '\n$ %s\n' "$component_command" >>"$log"
component_status=0
if (cd "$extract_dir" && APPIMAGE_EXTRACT_AND_RUN=1 "$appimage" --appimage-extract >/dev/null) >>"$log" 2>&1; then
  extracted="$extract_dir/squashfs-root"
  if [[ ! -d "$extracted" ]]; then
    component_status=1
    echo "AppImage extraction did not create squashfs-root" >>"$log"
  else
    for rel in usr/bin/runne-desktop usr/bin/runne usr/bin/runned usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json; do
      if [[ ! -f "$app_dir/$rel" || ! -f "$extracted/$rel" ]]; then
        echo "missing component: $rel" >>"$log"
        component_status=1
      elif cmp -s "$app_dir/$rel" "$extracted/$rel"; then
        echo "cmp -s '$app_dir/$rel' '$extracted/$rel': 0" >>"$log"
      else
        status=$?
        echo "cmp -s '$app_dir/$rel' '$extracted/$rel' exited $status" >>"$log"
        component_status=$status
      fi
    done
  fi
else
  component_status=$?
fi
[[ $test_status == 0 && $component_status == 0 ]] || {
  echo "qualification failed (desktop library tests=$test_status, AppImage components=$component_status); log: $log" >&2
  exit 1
}
require_clean_source
[[ "$(git rev-parse --verify HEAD^{commit})" == "$source_commit" ]] \
  || fail "source commit changed while qualification was running"

APP_DIR="$app_dir" APPIMAGE="$appimage" RECEIPT="$receipt" LOG="$log" SOURCE_COMMIT="$source_commit" \
TARGET="$target_json" TEST_COMMAND="$test_command" COMPONENT_COMMAND="$component_command" \
TEST_STATUS="$test_status" COMPONENT_STATUS="$component_status" python3 <<'PY'
import hashlib, json, os, pathlib, time

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

app = pathlib.Path(os.environ["APP_DIR"])
target = json.loads(pathlib.Path(os.environ["TARGET"]).read_text(encoding="utf-8"))
receipt = {
    "schemaVersion": 1,
    "artifactSha256": digest(os.environ["APPIMAGE"]),
    "sourceCommit": os.environ["SOURCE_COMMIT"],
    "releaseCandidateSha256": hashlib.sha256(os.environ["SOURCE_COMMIT"].encode("ascii")).hexdigest(),
    "desktopSha256": digest(app / "usr/bin/runne-desktop"),
    "cliSha256": digest(app / "usr/bin/runne"),
    "daemonSha256": digest(app / "usr/bin/runned"),
    "contractSha256": digest(app / "usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json"),
    "checks": ["desktop-library-tests", "appimage-component-match"],
    "checkCommands": [os.environ["TEST_COMMAND"], os.environ["COMPONENT_COMMAND"]],
    "checkExitStatuses": [int(os.environ["TEST_STATUS"]), int(os.environ["COMPONENT_STATUS"])],
    "checkLogSha256": digest(os.environ["LOG"]),
    "qualifiedAtUnixSeconds": int(time.time()),
    "expiresAtUnixSeconds": target["expiresAtUnixSeconds"],
}
with open(os.environ["RECEIPT"], "x", encoding="utf-8") as output:
    json.dump(receipt, output, separators=(",", ":"))
    output.write("\n")
PY
echo "Qualification receipt and check log created: $receipt"
