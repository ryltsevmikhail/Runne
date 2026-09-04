#!/usr/bin/env bash
set -euo pipefail

source scripts/macos-ci-keychain.sh
trap runne_ci_macos_keychain_cleanup EXIT

# The macOS self-hosted worker runs under launchd, which applies a default
# soft RLIMIT_NOFILE of 256 (unlike an interactive shell). The parallel daemon
# integration suite spawns in-process daemons plus many loopback TLS/TCP
# connections per test binary and legitimately exceeds that ceiling, so the
# connection-heavy tests fail with EMFILE ("Too many open files") and the
# store open path maps the same condition onto FileIdentityUncertain.
# Raise the soft limit before any cargo invocation.
ulimit -n 4096

MODE="${1:-}"
if [ "$MODE" != "pinned" ] && [ "$MODE" != "msrv" ]; then
    echo "Usage: bash scripts/ci.sh <pinned|msrv>"
    exit 1
fi

if [ "$MODE" = "pinned" ]; then
    EXPECTED="1.97.1"
else
    EXPECTED="1.95.0"
fi

# Resolve the mode's exact toolchain ourselves. The root rust-toolchain.toml
# pins the interactive default, and toolchain files take precedence over the
# RUSTUP_TOOLCHAIN env var (rustup >= 1.28), so an env override is not enough.
# `rustup which --toolchain` outranks the toolchain file; putting the resolved
# real bin dir first in PATH makes every later cargo/rustc call exact.
if command -v rustup &>/dev/null; then
    if TOOLCHAIN_BIN="$(rustup which --toolchain "$EXPECTED" cargo 2>/dev/null)"; then
        export PATH="$(dirname "$TOOLCHAIN_BIN"):$PATH"
    else
        echo "ERROR: rustup is present but toolchain $EXPECTED is not installed"
        echo "Run: rustup toolchain install $EXPECTED --profile minimal"
        exit 1
    fi
fi

RUSTC_VER=$(rustc --version 2>/dev/null | sed 's/rustc //' | cut -d' ' -f1)
if [ -z "$RUSTC_VER" ]; then
    echo "ERROR: rustc not found"
    exit 1
fi

if [ "$RUSTC_VER" != "$EXPECTED" ]; then
    echo "ERROR: Expected rustc $EXPECTED, got $RUSTC_VER"
    echo "Run: rustup run $EXPECTED bash scripts/ci.sh $MODE"
    exit 1
fi

stage_bundled_binary() {
    local package="$1"
    local bin="$2"
    local features="${3:-}"
    local host_target
    local extension=""
    local target_dir="${CARGO_TARGET_DIR:-target}"
    local source
    local destination
    host_target=$(rustc -vV | sed -n 's/^host: //p')
    if [[ "$host_target" == *windows* ]]; then
        extension=".exe"
    fi
    destination="apps/desktop/src-tauri/binaries/${bin}-${host_target}${extension}"
    echo "--- stage bundled $bin ($host_target) ---"
    if [ -n "$features" ]; then
        cargo build -p "$package" --bin "$bin" --release --features "$features" --locked
    else
        cargo build -p "$package" --bin "$bin" --release --locked
    fi
    source="${target_dir}/${host_target}/release/${bin}${extension}"
    if [ ! -f "$source" ]; then
        source="${target_dir}/release/${bin}${extension}"
    fi
    if [ ! -f "$source" ]; then
        echo "ERROR: bundled $bin was not produced for $host_target"
        exit 1
    fi
    mkdir -p "$(dirname "$destination")"
    cp "$source" "$destination"
    echo "staged bundled $bin: $destination"
}

# tauri.conf.json externalBin lists both the daemon and the CLI; the tauri
# build script fails when either binaries/<name>-<host-triple> is missing.
stage_bundled_binary runne-daemon runned desktop-protected
stage_bundled_binary runne-cli runne

echo "=== CI: $MODE mode (rustc $RUSTC_VER) ==="

if command -v python3 &>/dev/null; then
    PYTHON_BIN=python3
elif command -v python &>/dev/null; then
    PYTHON_BIN=python
else
    echo "ERROR: python not found"
    exit 1
fi

sha256_file() {
    "$PYTHON_BIN" -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

sha256_file_set() {
    "$PYTHON_BIN" -c 'import hashlib, pathlib, sys; h = hashlib.sha256(); [h.update(pathlib.Path(path).read_bytes()) for path in sys.argv[1:]]; print(h.hexdigest())' "$@"
}

# Record lock digest before
LOCK_DIGEST_BEFORE=$(sha256_file Cargo.lock)
PROFILE_FILES=(
    docs/profiles/opencode-baseline-inventory-v1.json
    docs/profiles/opencode-baseline-inventory-v1.digest
    docs/profiles/opencode-baseline-inventory-v2.json
    docs/profiles/opencode-baseline-inventory-v2.digest
    docs/schemas/opencode-baseline-inventory-v1.schema.json
    docs/schemas/opencode-baseline-inventory-v2.schema.json
)
PROFILE_DIGEST_BEFORE=$(sha256_file_set "${PROFILE_FILES[@]}")

if [ "$MODE" = "pinned" ]; then
    echo "--- fmt ---"
    cargo fmt --all --check

    echo "--- source file length ---"
    "$PYTHON_BIN" scripts/check-source-file-length.py --max-lines 300

    echo "--- Task 6C release exclusion ---"
    "$PYTHON_BIN" scripts/verify-task-6c-release-exclusion.py

    "$PYTHON_BIN" -m unittest \
        scripts.tests.test_check_deps \
        scripts.tests.test_check_deps_macos_process_identity \
        scripts.tests.test_check_source_file_length \
        scripts.desktop.tests.test_validate_architecture \
        scripts.tests.test_macos_ci_keychain \
        scripts.tests.test_verify_task_6c_release_exclusion \
        scripts.desktop.tests.test_legacy_cleanup_evidence \
        scripts.desktop.tests.test_legacy_cleanup_schema \
        scripts.desktop.tests.test_legacy_cleanup_cli \
        -v

    echo "--- check ---"
    cargo check --workspace --all-targets --all-features --locked

    echo "--- clippy ---"
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
else
    echo "--- check ---"
    cargo check --workspace --all-targets --all-features --locked
fi

if [ "$(/usr/bin/uname -s)" = "Darwin" ]; then
    # All-features enables the local native fixture route. Exercise the normal
    # writer configuration separately so no-service denial cannot be skipped.
    echo "--- test (production credential writer routing) ---"
    cargo test -p runne-secure-store --lib --no-default-features \
        --features provider-credential-broker-writer --locked native_authenticated
fi

echo "--- test (unit) ---"
runne_ci_macos_keychain_setup
cargo test --workspace --all-targets --all-features --locked

echo "--- test (doc) ---"
cargo test --workspace --doc --all-features --locked

echo "--- doc ---"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

echo "--- deps ---"
"$PYTHON_BIN" scripts/check-deps.py

echo "--- lock integrity ---"
LOCK_DIGEST_AFTER=$(sha256_file Cargo.lock)
if [ "$LOCK_DIGEST_BEFORE" != "$LOCK_DIGEST_AFTER" ]; then
    echo "ERROR: Cargo.lock changed during CI ($LOCK_DIGEST_BEFORE -> $LOCK_DIGEST_AFTER)"
    exit 1
fi
echo "Cargo.lock unchanged: $LOCK_DIGEST_BEFORE"

echo "--- profile artifact integrity ---"
PROFILE_DIGEST_AFTER=$(sha256_file_set "${PROFILE_FILES[@]}")
if [ "$PROFILE_DIGEST_BEFORE" != "$PROFILE_DIGEST_AFTER" ]; then
    echo "ERROR: profile artifacts changed during CI"
    exit 1
fi
echo "Profile artifacts unchanged: $PROFILE_DIGEST_BEFORE"

echo "=== CI $MODE: PASSED ==="
