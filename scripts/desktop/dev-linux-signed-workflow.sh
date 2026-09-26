#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat <<'USAGE'
Owner-dev Linux AppImage signing workflow (x86_64).

  dev-linux-signed-workflow.sh init
  dev-linux-signed-workflow.sh build PROFILE
  dev-linux-signed-workflow.sh finalize PROFILE

init creates a development keyset in Linux Secret Service and publishes only
its public manifest/root environment under target/dev-linux-metadata.
build compiles the public roots into desktop/daemon, creates the AppImage, and
stages its extracted AppDir. PROFILE is a new named isolated XDG profile.
finalize runs qualification checks, issues signed V2 metadata, and seeds journals.
GUI signed admission remains a separate post-signing check.
The qualification receipt is operational local evidence, not third-party
attestation; cryptographic provenance requires ops preprod qualification.
No sudo is used. Existing profile journals are never replaced or deleted.
USAGE
}

fail() { echo "error: $*" >&2; exit 1; }
require_clean_source() {
  git diff --quiet HEAD -- || fail "source tree has tracked changes; commit before packaging"
  [[ -z "$(git status --porcelain --untracked-files=all)" ]] \
    || fail "source tree has untracked files; commit or remove them before packaging"
}
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
command="${1:-}"
[[ -n "$command" ]] || { usage >&2; exit 2; }
shift
metadata="$repo_root/target/dev-linux-metadata"
manifest="$metadata/public-keys.json"
root_env="$metadata/update-root.env"
version="$(python3 -c 'import json; print(json.load(open("apps/desktop/src-tauri/tauri.conf.json"))["version"])')"

case "$command" in
  init)
    [[ $# == 0 ]] || fail "init takes no arguments"
    mkdir -p "$metadata"
    [[ ! -e "$manifest" && ! -e "$root_env" ]] || fail "keyset outputs already exist; refusing reinitialization"
    cargo build -p runne-update-metadata-producer --features dev-keyset-init
    target/debug/runne-update-metadata-producer init-dev-keyset \
      --public-manifest "$manifest" --key-store secret-service
    MANIFEST="$manifest" ROOT_ENV="$root_env" python3 <<'PY'
import json, os, re
manifest = json.load(open(os.environ["MANIFEST"], encoding="utf-8"))
mapping = {
    "RUNNE_UPDATE_ROOT_A_ID": "rootAId", "RUNNE_UPDATE_ROOT_A_HEX": "rootAHex",
    "RUNNE_UPDATE_ROOT_B_ID": "rootBId", "RUNNE_UPDATE_ROOT_B_HEX": "rootBHex",
    "RUNNE_UPDATE_ROOT_C_ID": "rootCId", "RUNNE_UPDATE_ROOT_C_HEX": "rootCHex",
    "RUNNE_UPDATE_SNAPSHOT_ID": "snapshotId", "RUNNE_UPDATE_SNAPSHOT_HEX": "snapshotHex",
    "RUNNE_UPDATE_TIMESTAMP_ID": "timestampId", "RUNNE_UPDATE_TIMESTAMP_HEX": "timestampHex",
}
with open(os.environ["ROOT_ENV"], "x", encoding="utf-8") as out:
    os.chmod(out.name, 0o600)
    for env, field in mapping.items():
        value = manifest[field]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise SystemExit("invalid public key manifest value")
        out.write(f"{env}={value}\n")
PY
    chmod 600 "$manifest" "$root_env"
    echo "Public development trust roots created; signing seeds remain in Secret Service."
    ;;
  build)
    [[ $# == 1 ]] || { usage >&2; exit 2; }
    profile="$1"
    [[ "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "invalid profile name"
    [[ -f "$root_env" ]] || fail "run init first"
    [[ "$(uname -s):$(uname -m)" == "Linux:x86_64" ]] || fail "requires Linux x86_64"
    require_clean_source
    data_home="$repo_root/target/dev-linux-profiles/$profile/data"
    app_out="$repo_root/target/dev-linux-profiles/$profile/artifacts"
    target_json="$repo_root/target/dev-linux-profiles/$profile/target.json"
    app_dir="$app_out/Runne.AppDir"
    profile_root="$repo_root/target/dev-linux-profiles/$profile"
    [[ ! -e "$profile_root" ]] || fail "named profile already exists; choose a fresh profile"
    mkdir -p "$app_out"
    updates="$data_home/com.runne.desktop/bundled-runtime/updates"
    [[ ! -d "$updates" ]] || fail "named profile already exists; choose a fresh profile"
    # Bind this named dev profile to the current source tree and Linux policy.
    source_commit="$(git rev-parse --verify HEAD^{commit})"
    PROFILE="$profile" VERSION="$version" TARGET_JSON="$target_json" SOURCE_COMMIT="$source_commit" python3 <<'PY'
import hashlib, json, os, time
now = int(time.time())
profile = os.environ["PROFILE"]
version = os.environ["VERSION"]
source_commit = os.environ["SOURCE_COMMIT"]
target = {
    "productId": "com.runne.desktop", "version": version, "platform": "linux",
    "arch": "x86_64", "artifactSha256": "0" * 64, "artifactSize": 0,
    "artifactUrl": f"https://updates.dev.runne.invalid/linux/Runne-{version}-x86_64.AppImage",
    "releaseCandidateSha256": hashlib.sha256(source_commit.encode("ascii")).hexdigest(),
    "minOs": "ubuntu-22.04",
    "profileId": f"dev-linux-{profile}", "bundleSha256": "0" * 64,
    "runtimeVersion": version, "runtimeDigest": "0" * 64, "channel": "dev",
    "publishedAtUnixSeconds": now, "expiresAtUnixSeconds": now + 14 * 86400,
    "rollbackFloor": "0.0.1", "nativeEnrollmentTuple": None,
    "nativeEnrollmentTupleV3": None, "qualificationBootstrapClientV1": None,
}
with open(os.environ["TARGET_JSON"], "x", encoding="utf-8") as out:
    json.dump(target, out, separators=(",", ":"))
    out.write("\n")
PY
    printf '%s\n' "$source_commit" > "$profile_root/source-commit.txt"
    # Prebuild packaged runtime and contract so their exact digests are compiled
    # into both the desktop and daemon consumers of the public trust root.
    set -a
    . "$root_env"
    set +a
    export RUNNE_UPDATE_PROFILE_ID="dev-linux-$profile"
    export RUNNE_UPDATE_RUNTIME_VERSION="$version"
    export RUNNE_UPDATE_CHANNEL=dev
    export RUNNE_UPDATE_ROLLBACK_FLOOR=0.0.1
    export RUNNE_UPDATE_METADATA_ENDPOINT="https://updates.dev.runne.invalid/linux/$profile.json"
    triple="$(rustc -vV | sed -n 's/^host: //p')"
    CARGO_TARGET_DIR=target/sidecars/runned cargo build --release --target "$triple" -p runne-daemon --bin runned --features desktop-protected
    runtime="target/sidecars/runned/$triple/release/runned"
    [[ -f "$runtime" ]] || fail "release daemon was not built"
    export RUNNE_UPDATE_RUNTIME_DIGEST="$(sha256sum "$runtime" | awk '{print $1}')"
    export RUNNE_UPDATE_BUNDLE_SHA256="$(sha256sum contracts/gocode-ui-client-3/bundle.json | awk '{print $1}')"
    export APPIMAGE_EXTRACT_AND_RUN=1 NO_STRIP=1
    source_app_dir="$repo_root/target/release/bundle/appimage/Runne.AppDir"
    rm -rf "$source_app_dir"
    if ! pnpm --filter @runne/desktop tauri build --bundles appimage; then
      [[ -d "$source_app_dir" ]] || fail "Tauri build failed before staging AppDir"
      echo "Tauri final bundling failed; using its staged AppDir with linuxdeploy." >&2
    fi
    [[ -d "$source_app_dir" ]] || fail "Tauri AppDir not found after first build"
    packaged_runtime_digest="$(sha256sum "$source_app_dir/usr/bin/runned" | awk '{print $1}')"
    [[ "$packaged_runtime_digest" =~ ^[0-9a-f]{64}$ ]] || fail "could not measure packaged daemon"
    export RUNNE_UPDATE_RUNTIME_DIGEST="$packaged_runtime_digest"
    cargo clean -p runne-desktop
    rm -rf "$source_app_dir"
    if ! pnpm --filter @runne/desktop tauri build --bundles appimage; then
      [[ -d "$source_app_dir" ]] || fail "second Tauri build failed before staging AppDir"
      echo "Tauri final bundling failed; using its staged AppDir with linuxdeploy." >&2
    fi
    [[ -d "$source_app_dir" ]] || fail "Tauri AppDir not found after second build"
    final_runtime_digest="$(sha256sum "$source_app_dir/usr/bin/runned" | awk '{print $1}')"
    [[ "$final_runtime_digest" == "$packaged_runtime_digest" ]] \
      || fail "packaged daemon digest changed between passes; refusing inconsistent trust binding"
    cp -a "$source_app_dir" "$app_dir"
    [[ "$(sha256sum "$app_dir/usr/bin/runned" | awk '{print $1}')" == "$RUNNE_UPDATE_RUNTIME_DIGEST" ]] \
      || fail "AppDir daemon digest differs from the digest compiled into desktop/daemon"
    [[ "$(sha256sum "$app_dir/usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json" | awk '{print $1}')" == "$RUNNE_UPDATE_BUNDLE_SHA256" ]] \
      || fail "AppDir contract digest differs from the digest compiled into desktop/daemon"
    linuxdeploy="${LINUXDEPLOY_BIN:-$HOME/.cache/tauri/linuxdeploy-x86_64.AppImage}"
    [[ -x "$linuxdeploy" ]] || fail "linuxdeploy AppImage missing: set LINUXDEPLOY_BIN"
    (cd "$app_out" && PATH="$HOME/.cache/tauri:$PATH" NO_STRIP=1 APPIMAGE_EXTRACT_AND_RUN=1 \
      "$linuxdeploy" --verbosity=1 --appdir="$app_dir" --output=appimage)
    appimage="$app_out/Runne-$version-x86_64.AppImage"
    [[ -f "$app_out/Runne-x86_64.AppImage" ]] || fail "linuxdeploy did not create its AppImage"
    mv "$app_out/Runne-x86_64.AppImage" "$appimage"
    (cd "$app_out" && APPIMAGE_EXTRACT_AND_RUN=1 "$appimage" --appimage-extract >/dev/null)
    [[ -d "$app_out/squashfs-root" ]] || fail "AppImage extraction did not create AppDir"
    for rel in usr/bin/runne-desktop usr/bin/runne usr/bin/runned usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json; do
      [[ -f "$app_dir/$rel" ]] || fail "AppDir lacks required tuple input: $rel"
      cmp -s "$app_dir/$rel" "$app_out/squashfs-root/$rel" || fail "AppImage changed measured input: $rel"
    done
    rm -rf "$app_out/squashfs-root"
    echo "Staged AppDir: $app_dir"
    echo "AppImage: $appimage"
    echo "Isolated XDG profile: $data_home"
    ;;
  finalize)
    [[ $# == 1 ]] || { usage >&2; exit 2; }
    profile="$1"
    [[ "$profile" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "invalid profile name"
    target_json="$repo_root/target/dev-linux-profiles/$profile/target.json"
    receipt="$repo_root/target/dev-linux-profiles/$profile/artifacts/qualification-v1.json"
    [[ -f "$root_env" && -f "$target_json" ]] || fail "missing trust roots or generated target policy; run init and build first"
    require_clean_source
    source_commit="$(git rev-parse --verify HEAD^{commit})"
    [[ "$(cat "$repo_root/target/dev-linux-profiles/$profile/source-commit.txt")" == "$source_commit" ]] \
      || fail "source commit changed since the AppImage build"
    [[ ! -e "$receipt" && ! -L "$receipt" ]] || fail "qualification receipt already exists; use a fresh profile"
    TARGET="$target_json" VERSION="$version" python3 <<'PY'
import json, os, re
from urllib.parse import urlparse
t = json.load(open(os.environ["TARGET"], encoding="utf-8"))
required = {"productId": "com.runne.desktop", "version": os.environ["VERSION"],
            "platform": "linux", "arch": "x86_64", "minOs": "ubuntu-22.04"}
if any(t.get(key) != value for key, value in required.items()):
    raise SystemExit("target policy must match this Linux x86_64 build")
for key in ("profileId", "channel", "rollbackFloor"):
    if not isinstance(t.get(key), str) or not t[key]:
        raise SystemExit(f"target policy is missing {key}")
if not re.fullmatch(r"[0-9a-f]{64}", t.get("releaseCandidateSha256", "")):
    raise SystemExit("target releaseCandidateSha256 must be lowercase SHA-256")
url = urlparse(t.get("artifactUrl", ""))
if url.scheme != "https" or not url.path.endswith(".AppImage"):
    raise SystemExit("artifactUrl must be HTTPS and end in .AppImage")
PY
    app_out="$repo_root/target/dev-linux-profiles/$profile/artifacts"
    app_dir="$app_out/Runne.AppDir"
    appimage="$app_out/Runne-$version-x86_64.AppImage"
    data_home="$repo_root/target/dev-linux-profiles/$profile/data"
    updates="$data_home/com.runne.desktop/bundled-runtime/updates"
    [[ -d "$app_dir" && -f "$appimage" ]] || fail "run build for this profile first"
    [[ ! -e "$updates" ]] || fail "profile journals already exist; refusing replacement"
    mkdir -p "$metadata"
    tuple="$app_out/linux-tuple-v2.json"
    draft="$app_out/draft.json"
    issued="$app_out/issued-metadata.json"
    [[ ! -e "$tuple" && ! -L "$tuple" && ! -e "$draft" && ! -L "$draft" \
      && ! -e "$issued" && ! -L "$issued" ]] || fail "finalization outputs already exist; use a fresh profile"
    cargo build -p runne-update-metadata-producer
    # Generate a new local evidence receipt inside finalize immediately before
    # tuple production and signing; a receipt from a prior qualify run is refused.
    RUNNE_FINALIZE_QUALIFICATION=1 \
      "$repo_root/scripts/desktop/dev-linux-qualification-receipt.sh" qualify "$profile"
    cargo run -p runne-platform-desktop --example linux_enrollment_tuple_v2 -- \
      --app-dir "$app_dir" --appimage "$appimage" --receipt "$receipt" --output "$tuple" \
      --target "$target_json" \
      --qualified-at "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["qualifiedAtUnixSeconds"])' "$receipt")" \
      --qualification-expires "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expiresAtUnixSeconds"])' "$receipt")"
    TUPLE="$tuple" DRAFT="$draft" TARGET="$target_json" APPIMAGE="$appimage" VERSION="$version" python3 <<'PY'
import json, os
t = json.load(open(os.environ["TUPLE"], encoding="utf-8"))
target = t["target"]
policy = json.load(open(os.environ["TARGET"], encoding="utf-8"))
for key in ("profileId", "channel", "releaseCandidateSha256", "rollbackFloor"):
    if target[key] != policy[key]:
        raise SystemExit(f"tuple policy mismatch: {key}")
draft = {
    "schemaVersion": 1, "artifactPath": os.path.realpath(os.environ["APPIMAGE"]),
    "artifactUrl": target["artifactUrl"], "productId": target["productId"],
    "version": target["version"], "currentVersion": target["version"],
    "platform": target["platform"], "arch": target["arch"],
    "releaseCandidateSha256": target["releaseCandidateSha256"], "minOs": target["minOs"],
    "profileId": target["profileId"], "bundleSha256": target["bundleSha256"],
    "runtimeVersion": target["runtimeVersion"], "runtimeDigest": target["runtimeDigest"],
    "channel": target["channel"], "publishedAtUnixSeconds": target["publishedAtUnixSeconds"],
    "expiresAtUnixSeconds": target["expiresAtUnixSeconds"], "rollbackFloor": target["rollbackFloor"],
    "rootVersion": 1, "targetsVersion": 1, "snapshotVersion": 1, "timestampVersion": 1,
    "nativeEnrollmentTupleV2Path": os.path.realpath(os.environ["TUPLE"]),
}
with open(os.environ["DRAFT"], "x", encoding="utf-8") as out:
    json.dump(draft, out, separators=(",", ":"))
    out.write("\n")
PY
    target/debug/runne-update-metadata-producer issue --draft "$draft" --output "$issued" --key-store secret-service
    PROFILE_DATA="$data_home" ISSUED="$issued" APPIMAGE="$appimage" python3 <<'PY'
import hashlib, json, os, pathlib
base = pathlib.Path(os.environ["PROFILE_DATA"]) / "com.runne.desktop/bundled-runtime/updates"
base.mkdir(parents=True, exist_ok=False)
metadata = pathlib.Path(os.environ["ISSUED"]).read_bytes().rstrip(b"\n")
issued = json.loads(metadata)
target = issued["targets"]["target"]
(base / "installed-metadata.json.1.json").write_bytes(metadata)
record = {"schemaVersion": 2, "state": "committed", "version": target["version"],
          "artifactSha256": target["artifactSha256"], "metadataSha256": hashlib.sha256(metadata).hexdigest(),
          "stagedPath": os.path.realpath(os.environ["APPIMAGE"])}
(base / "install-state.json.1.json").write_text(json.dumps(record, separators=(",", ":")))
trust = {"schemaVersion": 1, "rootVersion": issued["root"]["version"],
         "snapshotVersion": issued["snapshot"]["version"], "installedVersion": target["version"],
         "rollbackFloor": target["rollbackFloor"]}
(base / "trust-state.json.1.json").write_text(json.dumps(trust, separators=(",", ":")))
PY
    echo "V2 metadata and committed journals created in isolated profile $profile."
    echo "Qualification is operational local evidence, not third-party attestation; use ops preprod for cryptographic provenance."
    echo "Launch with: XDG_DATA_HOME='$data_home' '$appimage'"
    ;;
  *) usage >&2; exit 2 ;;
esac
