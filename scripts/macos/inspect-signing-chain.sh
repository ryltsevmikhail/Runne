#!/usr/bin/env bash
# Inspect the Runne macOS code-signing chain. Read-only; prints no secrets
# (entitlement plists and identity names are not secret; identity CN emails
# are masked).
#
# Two independent questions, deliberately separated:
#   Part 1 — can THIS artifact be launched: signature validity of every
#     chain member (app host, runne, runned, staged credential-service),
#     quarantine attribute, embedded provisioning profile presence/match.
#     A missing local identity does NOT affect this part.
#   Part 2 — can THIS host build and sign a NEW artifact: presence of
#     signing-capable identities ("valid identities only"; a merely found
#     certificate is not assumed signing-capable).
#
# Usage:
#   scripts/macos/inspect-signing-chain.sh path/to/Runne.app
#   scripts/macos/inspect-signing-chain.sh --self-test
set -euo pipefail

status=0
ADHOC_MEMBERS=""

say() { printf '\n== %s\n' "$1"; }
mask() { sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/[EMAIL]/g'; }

# Parse `security find-identity` output; print the number of identities that
# are signing-capable: numbered entries with a 40-hex SHA-1 (lower- or
# uppercase) under "Valid identities only" (falling back to non-invalid
# "Matching identities" entries when that header is absent, for tool
# variants that print a single section). Entries marked "(invalid)" and
# summary lines ("N identities found") are ignored.
parse_signing_capable_identities() {
    local output="$1"
    printf '%s\n' "$output" | awk '
        /^[[:space:]]*[0-9]+ (valid )?identit(y|ies) found/ { next }
        /Valid identities only/ { section = "valid"; seen_valid = 1; next }
        /Matching identities/ { section = "matching"; next }
        /^[[:space:]]*[0-9]+\)[[:space:]]+[0-9a-fA-F]{40}[[:space:]]/ {
            if ($0 ~ /\(invalid\)/) next
            if (section == "valid") valid++
            else if (section == "matching") matching++
        }
        END {
            if (seen_valid) print valid + 0
            else print matching + 0
        }
    '
}

self_test() {
    local failures=0 case_name expected actual output
    check() {
        expected="$1"; case_name="$2"; output="$3"
        actual="$(parse_signing_capable_identities "$output")"
        if [[ "$actual" == "$expected" ]]; then
            echo "ok   $case_name -> $actual"
        else
            echo "FAIL $case_name: expected $expected, got $actual"
            failures=$((failures + 1))
        fi
    }
    check 0 "zero identities" \
"Policy: Code Signing
  Matching identities
     0 identities found

  Valid identities only
     0 valid identities found
"
    check 1 "one valid identity" \
"Policy: Code Signing
  Matching identities
  1) abcdef0123456789abcdef0123456789abcdef01 \"Apple Development: dev (TEAM)\"
     1 identity found

  Valid identities only
  1) abcdef0123456789abcdef0123456789abcdef01 \"Apple Development: dev (TEAM)\"
     1 valid identity found
"
    check 1 "numbered uppercase SHA" \
"Policy: Code Signing
  Valid identities only
  2) ABCDEF0123456789ABCDEF0123456789ABCDEF01 \"Developer ID Application: ACME\"
     1 valid identity found
"
    check 1 "invalid identities do not count" \
"Policy: Code Signing
  Matching identities
  1) 1111111111111111111111111111111111111111 \"Expired Cert\"
  2) ABCDEF0123456789ABCDEF0123456789ABCDEF01 \"Good Cert\"
     2 identities found

  Valid identities only
  1) ABCDEF0123456789ABCDEF0123456789ABCDEF01 \"Good Cert\"
     1 valid identity found
"
    check 0 "invalid-only listing (no headers) counts zero" \
"  1) 1111111111111111111111111111111111111111 \"Broken Cert (invalid)\"
     1 identities found
"
    if [[ "$failures" -eq 0 ]]; then
        echo "self-test: all fixtures passed"
        return 0
    fi
    echo "self-test: $failures fixture(s) failed" >&2
    return 1
}

member() {
    local target="$1" label="$2" info flags entitlements verify_rc profile claimed_groups has_groups
    info="$(codesign -dv "$target" 2>&1 || true)"
    flags="$(printf '%s' "$info" | sed -n 's/.*flags=\(0x[0-9a-fx]*\).*/\1/p' | head -1)"
    entitlements="$(codesign -d --entitlements :- "$target" 2>/dev/null | plutil -convert json -o - - 2>/dev/null || echo '{}')"
    printf '%-28s flags=%-10s entitlements=%s\n' "$label" "${flags:-UNSIGNED}" "$entitlements"
    if ! codesign --verify --strict "$target" 2>/dev/null; then
        echo "  INVALID: strict verification failed for $label" >&2
        status=1
    fi
    if [[ -n "$flags" ]] && printf '%s' "$info" | grep -q 'adhoc'; then
        ADHOC_MEMBERS="$ADHOC_MEMBERS $label"
    fi
    # keychain-access-groups is a RESTRICTED entitlement (TN3125): the claim
    # must be authorized by an embedded provisioning profile.
    has_groups=0
    if printf '%s' "$entitlements" | grep -q 'keychain-access-groups'; then
        has_groups=1
    fi
    if [[ -d "$target" ]]; then
        profile="$target/Contents/embedded.provisionprofile"
        if [[ -f "$profile" ]]; then
            say "embedded provisioning profile of $label"
            security cms -D -i "$profile" 2>/dev/null \
                | plutil -extract Name raw -o - - 2>/dev/null | mask \
                | sed 's/^/  Name: /' || echo "  profile decode failed (inspection gap)"
            local app_id count index group allowed all_allowed
            app_id="$(security cms -D -i "$profile" 2>/dev/null \
                | plutil -extract Entitlements.application-identifier raw -o - - 2>/dev/null || echo '')"
            printf '  application-identifier: %s\n' "${app_id:-<absent — inspection gap>}"
            count="$(security cms -D -i "$profile" 2>/dev/null \
                | plutil -extract Entitlements.keychain-access-groups json -o - - 2>/dev/null \
                | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"
            all_allowed="ok"
            for ((index = 0; index < count; index++)); do
                group="$(security cms -D -i "$profile" 2>/dev/null \
                    | plutil -extract "Entitlements.keychain-access-groups.$index" raw -o - - 2>/dev/null || true)"
                printf '  profile group: %s\n' "$group"
            done
            if [[ "$has_groups" -eq 1 ]]; then
                echo "  claimed keychain-access-groups present; authorization depends on"
                echo "  the profile allowlist above (wildcards: prefix before '*')"
            fi
        elif [[ "$has_groups" -eq 1 ]]; then
            echo "  RISK: claims keychain-access-groups (restricted entitlement) with NO"
            echo "  embedded provisioning profile — at runtime this fails (TN3125/TN3137;"
            echo "  observed as -34018). Inspection gap: profile authorization unverified."
        else
            echo "  provisioning profile: ABSENT (expected: no restricted entitlements claimed)"
        fi
    elif [[ "$has_groups" -eq 1 ]]; then
        echo "  RISK: non-bundle target claims keychain-access-groups; a standalone"
        echo "  executable cannot embed a profile (TN3125) — wrap it app-like if the"
        echo "  claim is required (signing-a-daemon-with-a-restricted-entitlement)"
    fi
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit $?
fi

APP="${1:-}"
if [[ -z "$APP" || ! -d "$APP" ]]; then
    echo "usage: $0 path/to/Runne.app | $0 --self-test" >&2
    exit 64
fi

say "PART 1: launchability of the given artifact (independent of local identities)"
member "$APP" "Runne.app"
for helper in runne-desktop runne runned; do
    [[ -f "$APP/Contents/MacOS/$helper" ]] && member "$APP/Contents/MacOS/$helper" "$helper"
done
service_dir="$(find "$APP/Contents" -maxdepth 5 -name 'RunneCredentialService.app' -type d 2>/dev/null | head -1 || true)"
if [[ -n "$service_dir" ]]; then
    member "$service_dir" "credential-service(staged)"
    printf '%-28s %s\n' "staged at" "${service_dir#$APP/}"
else
    echo "credential-service: not staged in bundle (installed at enrollment time; inspection gap until then)"
fi
if xattr -l "$APP" 2>/dev/null | grep -q com.apple.quarantine; then
    echo "quarantine: PRESENT (Gatekeeper first-run policy may apply)"
else
    echo "quarantine: absent"
fi
echo "NOTE: signature state is a necessary, not sufficient launch condition;"
echo "the launch decision is observed only by actually running the artifact."

say "PART 2: build and sign capability of this host"
identity_list="$(security find-identity -p codesigning 2>/dev/null || true)"
printf '%s\n' "$identity_list" | sed -n '/Matching identities/,$p' | mask
count="$(parse_signing_capable_identities "$identity_list")"
printf 'signing-capable identities: %s\n' "$count"
if [[ "$count" -eq 0 ]]; then
    echo "This host cannot build AND sign a new enrollment-capable artifact:"
    echo "native enrollment requires a signature carrying keychain-access-groups"
    echo "authorized by provisioning (Apple TN3137), which ad-hoc signing cannot"
    echo "provide. Launching an already-properly-signed artifact stays possible."
    status=1
elif [[ -n "$ADHOC_MEMBERS" ]]; then
    echo "BLOCKER: identities are available but these chain members are still"
    echo "ad-hoc signed and were not re-signed with the available identity:$ADHOC_MEMBERS"
    status=1
fi

say "requirement summary"
echo "Secure Enclave seal key (runne-macos-keychain-acl) needs the Data Protection"
echo "keychain; its access groups must be authorized by provisioning (TN3137)."
echo "Local development: an identity whose provisioning authorizes the groups"
echo "(Apple Development + profile, or Developer ID + Developer ID profiles;"
echo "proposed path, not yet verified end-to-end). Distribution: Developer ID +"
echo "hardened runtime + notarization (profile requirement flagged as a risk)."

exit "$status"
