#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIRECTORY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

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

python3 "$SCRIPT_DIRECTORY/release_package/profile_metadata.py" \
    "$PROFILE_LIST" "$PROFILE_METADATA"

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

python3 "$SCRIPT_DIRECTORY/release_package/sbom.py" \
    "$CANDIDATE_DIRECTORY/sbom.cdx.json" "$VERSION"
LOCKFILE_DIGEST=$(sha256_file Cargo.lock)
DAEMON_DIGEST=$(sha256_file "$CANDIDATE_DIRECTORY/$BINARY_NAME")
CANDIDATE_DIGEST=$(python3 "$SCRIPT_DIRECTORY/release_package/candidate_digest.py" \
    "$SOURCE_REVISION" "$VERSION" "$LOCKFILE_DIGEST")

python3 "$SCRIPT_DIRECTORY/release_package/provenance.py" \
    "$CANDIDATE_DIRECTORY/provenance-attestation.json" "$CANDIDATE_DIGEST" \
    "$SOURCE_REVISION" "$TARGET" "$DAEMON_DIGEST" "$PROFILE_LIST"
python3 "$SCRIPT_DIRECTORY/release_package/checksums.py" "$CANDIDATE_DIRECTORY"
python3 "$SCRIPT_DIRECTORY/release_package/release_manifest.py" \
    "$CANDIDATE_DIRECTORY" "$VERSION" "$TARGET" "$PLATFORM" "$SOURCE_REVISION" \
    "$LOCKFILE_DIGEST" "$CANDIDATE_DIGEST" "$BINARY_NAME" "$DAEMON_DIGEST" \
    "$PROFILE_METADATA"
python3 "$SCRIPT_DIRECTORY/release_package/normalize_mtime.py" \
    "$CANDIDATE_DIRECTORY" "$SOURCE_DATE_EPOCH"

printf 'Packaged local assembled candidate: %s\n' "$CANDIDATE_DIRECTORY"
