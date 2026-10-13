# Canonical, fail-closed toolchain selection for scripts/ci.sh.
# Sourced after MODE and EXPECTED are set; may exit the caller on failure.
#
# rustup >= 1.28 auto-installs missing toolchains not only through proxy
# executables (rustc/cargo shims in ~/.cargo/bin) but also for `rustup
# which`, and CARGO_NET_OFFLINE covers cargo only, never rustup. The
# installed rustup documents the opt-out in-binary ("you may opt out with
# `RUSTUP_AUTO_INSTALL=0` or `rustup set auto-install disable`"), so every
# probe and every gate command spawned by this script runs with network
# auto-install disabled. This export scopes to the ci.sh subprocess
# environment only; it is not a receipt or host policy change.
export RUSTUP_AUTO_INSTALL=0

# Resolve the mode's exact toolchain ourselves. The root rust-toolchain.toml
# pins the interactive default, and toolchain files take precedence over the
# RUSTUP_TOOLCHAIN env var (rustup >= 1.28), so an env override is not enough.
# Selection order is fail-closed and never installs anything:
#   1. PATH pair first: when the PATH-resolved rustc AND cargo both report
#      exactly $EXPECTED (and a RUSTC override, when set, does too), keep
#      them. Inside the canonical receipt namespace the lane shims already
#      bind that exact hashed pair, and consulting rustup there resolves
#      against the empty scratch RUSTUP_HOME, which would auto-install a
#      toolchain over the network into the namespace.
#   2. rustup fallback: `rustup which --toolchain` outranks the toolchain
#      file, but it runs only with the EXACT name of an already-installed
#      toolchain taken from a successful `rustup toolchain list` (a failing
#      listing is never trusted even if its stdout matches, ambiguous or
#      foreign/custom candidates fail closed), and the resolved binary must
#      live under toolchains/<exact-name>/bin, so resolution stays local and
#      cannot trigger a download. A missing toolchain fails closed with the
#      install hint instead of being silently downloaded.
#   3. Final validation: the EFFECTIVE compiler cargo will use ($RUSTC when
#      set, else the PATH rustc) and the selected cargo must both report
#      exactly $EXPECTED; a wrong explicit RUSTC override is rejected with an
#      actionable error, never silently rewritten.

# Exact semantic version (first whitespace token after the program name) of
# `<tool> --version` output: full string equality against EXPECTED, so no
# substring or pre-release/suffix version is ever accepted.
_toolchain_version() {
    "$1" --version 2>/dev/null | sed 's/^[^ ]* //' | cut -d' ' -f1 || true
}

# Print the single exact installed toolchain name for $EXPECTED, or fail.
# `rustup which` with a partial name resolves to the DEFAULT host triple and
# would auto-install it, so only a full installed name from a successful
# listing may be passed on.
_rustup_exact_toolchain() {
    local listing name candidate
    if ! listing="$(rustup toolchain list 2>/dev/null)"; then
        return 1
    fi
    candidate=""
    while read -r name _; do
        case "$name" in
            "$EXPECTED"|"$EXPECTED"-*)
                if [ -n "$candidate" ]; then
                    return 1
                fi
                candidate="$name"
                ;;
        esac
    done <<<"$listing"
    if [ -z "$candidate" ]; then
        return 1
    fi
    printf '%s\n' "$candidate"
}

PATH_RUSTC="$(command -v rustc 2>/dev/null || true)"
PATH_CARGO="$(command -v cargo 2>/dev/null || true)"
PATH_RUSTC_VER=""
PATH_CARGO_VER=""
RUSTC_OVERRIDE_OK=1
if [ -n "$PATH_RUSTC" ]; then
    PATH_RUSTC_VER="$(_toolchain_version "$PATH_RUSTC")"
fi
if [ -n "$PATH_CARGO" ]; then
    PATH_CARGO_VER="$(_toolchain_version "$PATH_CARGO")"
fi
if [ -n "${RUSTC:-}" ] && [ "$(_toolchain_version "$RUSTC")" != "$EXPECTED" ]; then
    RUSTC_OVERRIDE_OK=0
fi

if [ "$PATH_RUSTC_VER" = "$EXPECTED" ] && [ "$PATH_CARGO_VER" = "$EXPECTED" ] \
    && [ "$RUSTC_OVERRIDE_OK" = "1" ]; then
    : # Exact expected pair already selected through PATH; rustup is not consulted.
elif ! command -v rustup &>/dev/null; then
    : # No rustup; the final validation below fails closed on any mismatch.
elif ! TOOLCHAIN_NAME="$(_rustup_exact_toolchain)"; then
    echo "ERROR: rustup is present but toolchain $EXPECTED is not installed"
    echo "Run: rustup toolchain install $EXPECTED --profile minimal"
    exit 1
elif ! TOOLCHAIN_BIN="$(rustup which --toolchain "$TOOLCHAIN_NAME" cargo 2>/dev/null)" \
    || [ -z "$TOOLCHAIN_BIN" ] || [ ! -x "$TOOLCHAIN_BIN" ] \
    || [ "$(basename "$(dirname "$(dirname "$TOOLCHAIN_BIN")")")" != "$TOOLCHAIN_NAME" ]; then
    echo "ERROR: rustup is present but toolchain $EXPECTED is not installed"
    echo "Run: rustup toolchain install $EXPECTED --profile minimal"
    exit 1
else
    export PATH="$(dirname "$TOOLCHAIN_BIN"):$PATH"
fi

# Final fail-closed validation of the EFFECTIVE toolchain pair after
# selection: the compiler cargo will actually use ($RUSTC when set, else
# the PATH-resolved rustc) and the selected cargo must both report exactly
# $EXPECTED.
EFFECTIVE_RUSTC="${RUSTC:-$(command -v rustc 2>/dev/null || true)}"
RUSTC_VER=""
if [ -n "$EFFECTIVE_RUSTC" ]; then
    RUSTC_VER="$(_toolchain_version "$EFFECTIVE_RUSTC")"
fi
if [ -z "$RUSTC_VER" ]; then
    echo "ERROR: rustc not found (effective compiler: ${RUSTC:-<PATH-resolved>})"
    exit 1
fi
if [ "$RUSTC_VER" != "$EXPECTED" ]; then
    echo "ERROR: Expected rustc $EXPECTED, got $RUSTC_VER (effective: $EFFECTIVE_RUSTC)"
    echo "Run: rustup run $EXPECTED bash scripts/ci.sh $MODE"
    exit 1
fi
CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
CARGO_VER=""
if [ -n "$CARGO_BIN" ]; then
    CARGO_VER="$(_toolchain_version "$CARGO_BIN")"
fi
if [ -z "$CARGO_VER" ]; then
    echo "ERROR: cargo not found"
    echo "Run: rustup run $EXPECTED bash scripts/ci.sh $MODE"
    exit 1
fi
if [ "$CARGO_VER" != "$EXPECTED" ]; then
    echo "ERROR: Expected cargo $EXPECTED, got $CARGO_VER (selected: $CARGO_BIN)"
    echo "Run: rustup run $EXPECTED bash scripts/ci.sh $MODE"
    exit 1
fi

# Provenance for the receipt log: record exactly which binaries were selected.
echo "selected rustc: $EFFECTIVE_RUSTC"
echo "selected cargo: $CARGO_BIN"
echo "effective RUSTC override: ${RUSTC:-none}"
