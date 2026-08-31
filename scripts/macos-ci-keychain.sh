#!/usr/bin/env bash

# This file is sourced by scripts/ci.sh. The canonical local gate replaces
# HOME with a private empty directory, so native Keychain tests must use a
# a disposable explicit Keychain instead of reaching the user's login Keychain.

runne_ci_macos_keychain_cleanup() {
    if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
        return 0
    fi

    local cleanup_status=0
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN:-}" ] && [ -e "$RUNNE_CI_MACOS_KEYCHAIN" ]; then
        /usr/bin/security delete-keychain "$RUNNE_CI_MACOS_KEYCHAIN" || cleanup_status=1
    fi
    if [ -n "${RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY:-}" ]; then
        /bin/rmdir "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY" 2>/dev/null || cleanup_status=1
        /bin/rmdir "$(/usr/bin/dirname "$RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY")" \
            2>/dev/null || cleanup_status=1
    fi
    unset RUNNE_CI_MACOS_KEYCHAIN RUNNE_CI_MACOS_KEYCHAIN_DIRECTORY
    return "$cleanup_status"
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
    /usr/bin/security create-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security set-keychain-settings "$RUNNE_CI_MACOS_KEYCHAIN"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$RUNNE_CI_MACOS_KEYCHAIN"
}
