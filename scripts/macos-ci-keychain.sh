#!/usr/bin/env bash

# This file is sourced by scripts/ci.sh. The canonical local gate replaces
# HOME with a private empty directory, so native Keychain tests must use a
# a disposable explicit Keychain instead of reaching the user's login Keychain.
#
# The keychain path is a load-bearing contract: Rust consumers
# (runne-secure-store active_keychain, platform-desktop fixtures, the
# provider-credential broker and the local native enrollment test route)
# require exactly $HOME/Library/Keychains/runne-ci.keychain-db, so per-process
# relocation is not allowed. Isolation comes from the worker's serialized
# mac slots plus the idempotent stale-keychain deregistration below.

runne_ci_macos_keychain_cleanup() {
    if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
        return 0
    fi

    # Cleanup must be best-effort: this runs from an EXIT trap in ci.sh under
    # `set -e`, and a non-zero return there overrides the script's successful
    # exit status, marking a PASSED cube as failed. On the real worker the
    # keychain directory is the user's ~/Library/Keychains, which is never
    # empty — the rmdirs only succeed under an isolated HOME and must not
    # fail the run otherwise. A leftover from a killed run is deregistered
    # idempotently by the next setup.
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN:-}" ]; then
        /usr/bin/security delete-keychain "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null \
            || echo "warn: skipped keychain deregister: $RUNNE_CI_MACOS_KEYCHAIN" >&2
        /bin/rm -f "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null || true
    fi
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY:-}" ]; then
        /bin/rmdir "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY" 2>/dev/null || true
        /bin/rmdir "$(/usr/bin/dirname "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY")" \
            2>/dev/null || true
    fi
    unset RUNNE_CI_MACOS_KEYCHAIN RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY
    return 0
}

runne_ci_macos_keychain_setup() {
    if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
        return 0
    fi

    RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY="$HOME/Library/Keychains"
    RUNNE_CI_MACOS_KEYCHAIN="$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY/runne-ci.keychain-db"
    export RUNNE_CI_MACOS_KEYCHAIN RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY
    local keychain_password="runne-ci-isolated-keychain"

    /bin/mkdir -p "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY"
    /bin/chmod 700 "$HOME/Library" "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY"
    # A task killed by its timeout leaves the keychain behind, so setup must
    # be idempotent or every subsequent task fails at create.
    /usr/bin/security delete-keychain "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null || true
    /bin/rm -f "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null || true
    /usr/bin/security create-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security set-keychain-settings "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
}
