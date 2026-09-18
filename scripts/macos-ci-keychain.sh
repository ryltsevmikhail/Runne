#!/usr/bin/env bash

# This file is sourced by scripts/ci.sh. The canonical local gate replaces
# HOME with a private empty directory, so native Keychain tests must use a
# a disposable explicit Keychain instead of reaching the user's login Keychain.

runne_ci_macos_keychain_cleanup() {
    if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
        return 0
    fi

    # Cleanup must be best-effort: this runs from an EXIT trap in ci.sh under
    # `set -e`, and a non-zero return there overrides the script's successful
    # exit status, marking a PASSED cube as failed. Stale leftovers from a
    # killed run are already handled idempotently by setup on the next run.
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN:-}" ]; then
        /usr/bin/security delete-keychain "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null \
            || echo "warn: skipped keychain deregister: $RUNNE_CI_MACOS_KEYCHAIN" >&2
        /bin/rm -f "$RUNNE_CI_MACOS_KEYCHAIN" 2>/dev/null || true
    fi
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY:-}" ]; then
        /bin/rmdir "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY" 2>/dev/null || true
    fi
    unset RUNNE_CI_MACOS_KEYCHAIN RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY
    return 0
}

runne_ci_macos_keychain_setup() {
    if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
        return 0
    fi

    # One disposable directory per process: the runtime-ci macos-pinned and
    # macos-msrv cubes can run concurrently on the same self-hosted worker,
    # and a fixed keychain path let one cube's setup destroy a keychain that
    # the other cube's tests were actively using.
    local directory
    directory="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/runne-ci-keychain.XXXXXX")"
    RUNNE_CI_MACOS_KEYCHAIN="$directory/runne-ci.keychain-db"
    RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY="$directory"
    export RUNNE_CI_MACOS_KEYCHAIN RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY
    local keychain_password="runne-ci-isolated-keychain"

    /usr/bin/security create-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security set-keychain-settings "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
}
