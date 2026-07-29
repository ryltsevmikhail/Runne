#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'Usage: %s --version <semver> --target <target> --output <empty-directory>\n' "$0" >&2
    exit 1
}

sha256_file() {
    python3 -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

VERSION=''
TARGET=''
OUTPUT=''
CARGO_BIN="${CARGO:-cargo}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || usage
            [ -z "$VERSION" ] || fail 'duplicate option: --version'
            VERSION="$2"
            shift 2
            ;;
        --target)
            [ "$#" -ge 2 ] || usage
            [ -z "$TARGET" ] || fail 'duplicate option: --target'
            TARGET="$2"
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || usage
            [ -z "$OUTPUT" ] || fail 'duplicate option: --output'
            OUTPUT="$2"
            shift 2
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

[ -n "$VERSION" ] && [ -n "$TARGET" ] && [ -n "$OUTPUT" ] || usage
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] \
    || fail 'version must be SemVer without build metadata'

case "$TARGET" in
    aarch64-apple-darwin|x86_64-apple-darwin) PLATFORM='macos' ;;
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) PLATFORM='linux' ;;
    x86_64-pc-windows-msvc) PLATFORM='windows' ;;
    *) fail "unsupported target: $TARGET" ;;
esac

[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] || fail 'SOURCE_DATE_EPOCH must be set to a non-negative integer'

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'must run inside a Git worktree'
cd "$REPO_ROOT"
SOURCE_REVISION=$(git rev-parse --verify HEAD^{commit} 2>/dev/null) || fail 'HEAD must resolve to an exact commit'
[[ "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] || fail 'HEAD must be a lowercase 40-hex commit SHA'
git diff --quiet || fail 'tracked working tree is dirty'
git diff --cached --quiet || fail 'tracked working tree is dirty'

if [ -e "$OUTPUT" ]; then
    [ -d "$OUTPUT" ] || fail 'output path must be a directory'
    [ -z "$(find "$OUTPUT" -mindepth 1 -print -quit)" ] || fail 'output directory must be empty'
fi

[ -f Cargo.lock ] || fail 'Cargo.lock is required'
[ -f LICENSE ] || fail 'LICENSE is required'
[ -d docs/profiles ] || fail 'docs/profiles is required'

PROFILE_LIST=$(mktemp)
PROFILE_METADATA=$(mktemp)
trap 'rm -f "$PROFILE_LIST" "$PROFILE_METADATA"' EXIT
find docs/profiles -maxdepth 1 -type f -name '*.json' -print | LC_ALL=C sort > "$PROFILE_LIST"
[ -s "$PROFILE_LIST" ] || fail 'at least one profile artifact is required'

while IFS= read -r profile; do
    sidecar="${profile%.json}.digest"
    [ -f "$sidecar" ] || fail "missing profile digest sidecar: $sidecar"
    actual=$(sha256_file "$profile")
    expected=$(tr -d '\r\n' < "$sidecar")
    [ "$expected" = "sha256:$actual" ] || fail "profile digest mismatch: $profile"
done < "$PROFILE_LIST"

python3 - "$PROFILE_LIST" "$PROFILE_METADATA" <<'PY'
import json
import pathlib
import sys

profiles = []
for raw_path in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    source = pathlib.Path(raw_path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"ERROR: invalid profile JSON: {source}: {error}") from error
    if not isinstance(payload, dict):
        raise SystemExit(f"ERROR: profile JSON must be an object: {source}")
    name = payload.get("profile_id")
    if not isinstance(name, str) or not name:
        raise SystemExit(f"ERROR: profile_id is required: {source}")
    revision = payload.get("profile_revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise SystemExit(f"ERROR: profile_revision is required: {source}")
    profiles.append({"name": name, "revision": revision, "source_path": raw_path})
pathlib.Path(sys.argv[2]).write_bytes(
    json.dumps(profiles, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
)
PY

CANDIDATE_NAME="gocode-runtime-$VERSION-$TARGET"
CANDIDATE_DIRECTORY="$OUTPUT/$CANDIDATE_NAME"

"$CARGO_BIN" build --locked --release --bin gocode-daemon --target "$TARGET"
BINARY_NAME='gocode-daemon'
if [ "$PLATFORM" = 'windows' ]; then
    BINARY_NAME='gocode-daemon.exe'
fi
BINARY_PATH="target/$TARGET/release/$BINARY_NAME"
[ -f "$BINARY_PATH" ] || fail "required daemon artifact is missing: $BINARY_PATH"

mkdir -p "$OUTPUT"
[ ! -e "$CANDIDATE_DIRECTORY" ] || fail 'candidate staging directory already exists'
mkdir -p "$CANDIDATE_DIRECTORY/LICENSES"
install -m 0755 "$BINARY_PATH" "$CANDIDATE_DIRECTORY/$BINARY_NAME"
install -m 0644 LICENSE "$CANDIDATE_DIRECTORY/LICENSES/LICENSE"
mkdir -p "$CANDIDATE_DIRECTORY/profiles"
while IFS= read -r profile; do
    install -m 0644 "$profile" "$CANDIDATE_DIRECTORY/profiles/$(basename "$profile")"
done < "$PROFILE_LIST"

python3 - "$CANDIDATE_DIRECTORY/sbom.cdx.json" "$VERSION" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = {
    "bomFormat": "CycloneDX",
    "components": [{"name": "gocode-daemon", "type": "application", "version": sys.argv[2]}],
    "specVersion": "1.5",
}
path.write_bytes(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
PY

LOCKFILE_DIGEST=$(sha256_file Cargo.lock)
DAEMON_DIGEST=$(sha256_file "$CANDIDATE_DIRECTORY/$BINARY_NAME")

CANDIDATE_DIGEST=$(python3 - "$SOURCE_REVISION" "$VERSION" "$LOCKFILE_DIGEST" <<'PY'
import hashlib
import json
import sys

lanes = []
for lane_id, version in (("pinned-1.97.1", "1.97.1"), ("msrv-1.95.0", "1.95.0")):
    lanes.append({
        "cargo_version": version,
        "hosted_execution_slots": [
            {"platform": platform, "status": "planned"}
            for platform in ("linux", "macos", "windows")
        ],
        "lane_id": lane_id,
        "rustc_version": version,
    })
candidate = {
    "lockfile_digest": sys.argv[3],
    "qualification_lanes": lanes,
    "release_version": sys.argv[2],
    "source_revision": sys.argv[1],
}
encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
PY
)

python3 - "$CANDIDATE_DIRECTORY/provenance-attestation.json" "$CANDIDATE_DIGEST" "$SOURCE_REVISION" "$TARGET" "$DAEMON_DIGEST" "$PROFILE_LIST" <<'PY'
import hashlib
import json
import pathlib
import sys

profiles = [pathlib.Path(path) for path in pathlib.Path(sys.argv[6]).read_text(encoding="utf-8").splitlines()]
lanes = []
for lane_id, version in (("pinned-1.97.1", "1.97.1"), ("msrv-1.95.0", "1.95.0")):
    lanes.append({
        "cargo_version": version,
        "hosted_execution_slots": [
            {"platform": platform, "status": "planned"}
            for platform in ("linux", "macos", "windows")
        ],
        "lane_id": lane_id,
        "rustc_version": version,
    })
payload = {
    "artifact_sha256": sys.argv[5],
    "candidate_digest": sys.argv[2],
    "profile_digests": [hashlib.sha256(profile.read_bytes()).hexdigest() for profile in profiles],
    "qualification_lanes": lanes,
    "source_revision": sys.argv[3],
    "target": sys.argv[4],
}
pathlib.Path(sys.argv[1]).write_bytes(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
)
PY

python3 - "$CANDIDATE_DIRECTORY" <<'PY'
import hashlib
import pathlib
import sys

candidate_directory = pathlib.Path(sys.argv[1])
entries = []
for path in candidate_directory.rglob("*"):
    if not path.is_file() or path.name in {"checksums.sha256", "release-manifest.v1.json"}:
        continue
    relative = path.relative_to(candidate_directory).as_posix()
    entries.append((relative.encode("utf-8"), hashlib.sha256(path.read_bytes()).hexdigest(), relative))
entries.sort(key=lambda entry: entry[0])
(candidate_directory / "checksums.sha256").write_text(
    "".join(f"{digest}  {relative}\n" for _, digest, relative in entries), encoding="utf-8"
)
PY

python3 - "$CANDIDATE_DIRECTORY" "$VERSION" "$TARGET" "$PLATFORM" "$SOURCE_REVISION" "$LOCKFILE_DIGEST" "$CANDIDATE_DIGEST" "$BINARY_NAME" "$DAEMON_DIGEST" "$PROFILE_METADATA" <<'PY'
import hashlib
import json
import pathlib
import sys

candidate_directory = pathlib.Path(sys.argv[1])
version, target, platform, source_revision, lockfile_digest, candidate_digest, binary_name, daemon_digest = sys.argv[2:10]
profile_metadata = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))

profiles = []
for profile in profile_metadata:
    source = pathlib.Path(profile["source_path"])
    copied_path = f"profiles/{source.name}"
    profiles.append({
        "name": profile["name"],
        "path": copied_path,
        "revision": profile["revision"],
        "sha256": hashlib.sha256((candidate_directory / copied_path).read_bytes()).hexdigest(),
    })
profiles.sort(key=lambda profile: profile["path"].encode("utf-8"))
profile_digests = [profile["sha256"] for profile in profiles]

lanes = []
for lane_id, lane_version in (("pinned-1.97.1", "1.97.1"), ("msrv-1.95.0", "1.95.0")):
    lanes.append({
        "cargo_version": lane_version,
        "hosted_execution_slots": [
            {"platform": slot_platform, "status": "planned"}
            for slot_platform in ("linux", "macos", "windows")
        ],
        "lane_id": lane_id,
        "rustc_version": lane_version,
    })

checksums_path = candidate_directory / "checksums.sha256"
sbom_path = candidate_directory / "sbom.cdx.json"
provenance_path = candidate_directory / "provenance-attestation.json"
artifact_path = binary_name
evidence = []
for gate_id, kind, path, digest in (
    ("package", "package", artifact_path, daemon_digest),
    ("checksums", "checksums", "checksums.sha256", hashlib.sha256(checksums_path.read_bytes()).hexdigest()),
    ("provenance-attestation", "provenance-attestation", "provenance-attestation.json", hashlib.sha256(provenance_path.read_bytes()).hexdigest()),
    ("sbom", "sbom", "sbom.cdx.json", hashlib.sha256(sbom_path.read_bytes()).hexdigest()),
):
    evidence.append({
        "artifact_sha256": daemon_digest,
        "candidate_digest": candidate_digest,
        "gate_id": gate_id,
        "kind": kind,
        "platform": platform,
        "profile_digests": profile_digests,
        "sha256": digest,
        "source_revision": source_revision,
        "uri": f"candidate://{candidate_directory.name}/{path}",
    })

manifest = {
    "artifacts": [
        {"kind": "daemon", "path": artifact_path, "sha256": daemon_digest, "target": target},
        {"kind": "license", "path": "LICENSES/LICENSE", "sha256": hashlib.sha256((candidate_directory / "LICENSES/LICENSE").read_bytes()).hexdigest(), "target": target},
        {"kind": "sbom", "path": "sbom.cdx.json", "sha256": hashlib.sha256(sbom_path.read_bytes()).hexdigest(), "target": target},
    ],
    "candidate": {
        "lockfile_digest": lockfile_digest,
        "qualification_lanes": lanes,
        "release_version": version,
        "source_revision": source_revision,
    },
    "evidence": evidence,
    "format": "release-manifest.v1",
    "platforms": [{"artifact_sha256": daemon_digest, "os": platform, "profile_digests": profile_digests, "target": target}],
    "profiles": profiles,
    "qualification_state": "assembled",
}
(candidate_directory / "release-manifest.v1.json").write_bytes(
    json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
)
PY

python3 - "$CANDIDATE_DIRECTORY" "$SOURCE_DATE_EPOCH" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
timestamp = int(sys.argv[2])
def set_mtime(path):
    try:
        os.utime(path, (timestamp, timestamp), follow_symlinks=False)
    except NotImplementedError:
        os.utime(path, (timestamp, timestamp))

for path in sorted(root.rglob("*"), key=lambda item: str(item).encode("utf-8"), reverse=True):
    set_mtime(path)
set_mtime(root)
PY

printf 'Packaged local assembled candidate: %s\n' "$CANDIDATE_DIRECTORY"
