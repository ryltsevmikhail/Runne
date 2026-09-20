#!/usr/bin/env bash
# Inspect the Runne macOS code-signing chain: signatures, entitlements and
# identity availability for every process that participates in native
# enrollment (app host, bundled sidecars, staged credential-service).
#
# Read-only diagnostics; prints no secrets (entitlement plists and identity
# names are not secret). Exits non-zero when a blocking condition is found.
#
# Usage: scripts/macos/inspect-signing-chain.sh [path/to/Runne.app]
set -euo pipefail

APP="${1:-}"
if [[ -z "$APP" || ! -d "$APP" ]]; then
    echo "usage: $0 path/to/Runne.app" >&2
    exit 64
fi

status=0
ADHOC_MEMBERS=""

say() { printf '\n== %s\n' "$1"; }

member() {
    local target="$1" label="$2" info flags entitlements
    info="$(codesign -dv "$target" 2>&1 || true)"
    flags="$(printf '%s' "$info" | sed -n 's/.*flags=\(0x[0-9a-fx]*\).*/\1/p' | head -1)"
    entitlements="$(codesign -d --entitlements :- "$target" 2>/dev/null | plutil -convert json -o - - 2>/dev/null || echo '{}')"
    printf '%-24s flags=%-10s entitlements=%s\n' "$label" "${flags:-UNSIGNED}" "$entitlements"
    if [[ -z "$flags" ]]; then
        status=1
    elif [[ "$flags" != *linker-signed* ]] && printf '%s' "$info" | grep -q 'adhoc'; then
        # Explicitly ad-hoc re-signed member: cannot carry keychain entitlements.
        ADHOC_MEMBERS="$ADHOC_MEMBERS $label"
    fi
}

say "signing identities available (codesigning)"
identity_list="$(security find-identity -p codesigning 2>/dev/null || true)"
# Identity CNs may embed the developer's email; mask it.
printf '%s\n' "$identity_list" | sed -n '/Matching identities/,$p' \
    | sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/[EMAIL]/g'
count="$(printf '%s\n' "$identity_list" | grep -cE '^[[:space:]]*[0-9a-f]{40}' || true)"
printf 'identities: %s\n' "$count"
if [[ "$count" -eq 0 ]]; then
    echo "BLOCKER: no code signing identities; native enrollment requires a real" >&2
    echo "identity (Apple Development for local run, Developer ID for distribution)." >&2
    echo "Ad-hoc signatures cannot carry keychain-access-groups on macOS 27:" >&2
    echo "embedding them makes the bundle un-launchable (launchd spawn error 163)," >&2
    echo "and without them Secure Enclave key creation fails errSecMissingEntitlement (-34018)." >&2
    status=1
fi

say "chain members of $APP"
member "$APP" "Runne.app"
for helper in runne-desktop runne runned; do
    if [[ -f "$APP/Contents/MacOS/$helper" ]]; then
        member "$APP/Contents/MacOS/$helper" "$helper"
    fi
done

staged_service="$APP/Contents/Resources/native-enrollment/RunneCredentialService.app"
service_dir="$(find "$APP/Contents" -maxdepth 5 -name 'RunneCredentialService.app' -type d 2>/dev/null | head -1 || true)"
if [[ -n "$service_dir" ]]; then
    member "$service_dir" "credential-service(staged)"
    printf '%-24s %s\n' "staged at" "${service_dir#$APP/}"
else
    echo "credential-service: not staged in bundle (installed at enrollment time)"
fi

if [[ "$count" -gt 0 && -n "$ADHOC_MEMBERS" ]]; then
    echo "BLOCKER: identities are available but these chain members are still" >&2
    echo "ad-hoc signed and were not re-signed with the available identity:$ADHOC_MEMBERS" >&2
    status=1
fi

say "chain consistency"
for helper in runne-desktop runne runned; do
    target="$APP/Contents/MacOS/$helper"
    [[ -f "$target" ]] || continue
    if ! codesign --verify --strict "$target" 2>/dev/null; then
        echo "INVALID: $helper signature" >&2
        status=1
    fi
done
if ! codesign --verify --strict "$APP" 2>/dev/null; then
    echo "INVALID: bundle signature" >&2
    status=1
fi
codesign -dv "$APP" 2>&1 | sed -n 's/.*Signature=\(.*\)/outer bundle signature: \1/p'

say "requirement summary (see task-macos-native-enrollment-devrun-report.md)"
echo "Secure Enclave seal key (runne-macos-keychain-acl) needs the Data Protection"
echo "keychain; its access groups must be authorized by provisioning (Apple TN3137)."
echo "Local development: Apple Development identity + provisioning profile."
echo "Distribution: Developer ID Application identity + hardened runtime + notarization."

exit "$status"
