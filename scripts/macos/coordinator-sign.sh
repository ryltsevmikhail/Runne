#!/usr/bin/env bash
# Coordinator-side (Mac with the signing identity): verify the transferred
# artifact against its manifest, embed provisioning profiles, sign the chain
# inner-first with a Developer ID Application identity, and emit a return
# manifest with post-sign SHA-256 values and CDHashes for transfer
# verification on the build host.
#
# The private key never leaves the coordinator host; this script only drives
# `codesign`. It refuses to sign members claiming the RESTRICTED
# keychain-access-groups entitlement when no provisioning profile covers
# them (TN3125) unless --accept-unauthorized-restricted-claims is given.
#
# Usage:
#   coordinator-sign.sh --identity "Developer ID Application: NAME (TEAM)" \
#     --app path/to/Runne.app --manifest manifest.json \
#     --entitlements-dir path/to/repo/apps/desktop/src-tauri/macos \
#     --profile-desktop desktop.provisionprofile \
#     [--profile-credential-service credential-service.provisionprofile] \
#     [--output return-manifest.json] [--dry-run]
set -euo pipefail

IDENTITY=""; APP=""; MANIFEST=""; ENTS_DIR=""; PROFILE_DESKTOP=""; PROFILE_CRED=""
OUTPUT="return-manifest.json"; DRY_RUN=0; ACCEPT_UNAUTHORIZED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity) IDENTITY="$2"; shift 2 ;;
        --app) APP="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --entitlements-dir) ENTS_DIR="$2"; shift 2 ;;
        --profile-desktop) PROFILE_DESKTOP="$2"; shift 2 ;;
        --profile-credential-service) PROFILE_CRED="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --accept-unauthorized-restricted-claims) ACCEPT_UNAUTHORIZED=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done
[[ -n "$IDENTITY" && -n "$APP" && -n "$MANIFEST" && -n "$ENTS_DIR" ]] || { echo "missing required options" >&2; exit 64; }
[[ -d "$APP" && -f "$MANIFEST" && -d "$ENTS_DIR" ]] || { echo "missing input paths" >&2; exit 64; }

sha() { shasum -a 256 "$1" | awk '{print $1}'; }
PLAN="$(mktemp /tmp/runne-coordinator-plan.XXXXXX)"
RESULTS="$(mktemp /tmp/runne-coordinator-result.XXXXXX)"
trap 'rm -f "$PLAN" "$RESULTS"' EXIT
tree_sha() {
    python3 - "$1" <<'EOF'
import hashlib, os, sys
root = sys.argv[1]
digest = hashlib.sha256()
if os.path.isfile(root):
    with open(root, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    print(digest.hexdigest())
    raise SystemExit(0)
for base, dirs, files in sorted(os.walk(root)):
    dirs.sort()
    for name in sorted(files):
        full = os.path.join(base, name)
        digest.update(os.path.relpath(full, root).encode())
        with open(full, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
print(digest.hexdigest())
EOF
}

APP_ROOT="$(cd "$APP/.." && pwd)"
run() { if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY-RUN: $*"; else "$@"; fi }

python3 - "$MANIFEST" > "$PLAN" <<'EOF'
import json, sys
manifest = json.load(open(sys.argv[1]))
for member in manifest["members"]:
    print(f"{member['path']}\t{member['sha256_pre']}\t{member['entitlements']}\t{member['member']}")
EOF

say() { printf '\n== %s\n' "$1"; }
say "transfer verification (pre-sign SHA-256 from manifest)"
while IFS=$'\t' read -r path expected ents member; do
    actual="$(tree_sha "$APP_ROOT/$path")"
    if [[ "$actual" != "$expected" ]]; then
        echo "MISMATCH for $member: manifest=$expected actual=$actual" >&2
        exit 65
    fi
    echo "ok   $member"
done < "$PLAN"


say "pre-flight: entitlements files and team prefix"
TEAM_FROM_IDENTITY="$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')"
while IFS=$'\t' read -r path expected ents member; do
    entitlements="$ENTS_DIR/${ents#macos/}"
    if [[ ! -f "$entitlements" ]]; then
        echo "REFUSED: entitlements file for $member not found: $entitlements" >&2
        echo "Signing without declared entitlements would silently produce an" >&2
        echo "artifact that fails native enrollment." >&2
        exit 66
    fi
    if [[ -n "$TEAM_FROM_IDENTITY" ]]; then
        app_id="$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$entitlements" 2>/dev/null || true)"
        if [[ -n "$app_id" && "$app_id" != "$TEAM_FROM_IDENTITY".* ]]; then
            echo "REFUSED: entitlement application-identifier '$app_id' does not" >&2
            echo "match the signing identity team '$TEAM_FROM_IDENTITY' ($member)." >&2
            exit 66
        fi
    fi
done < "$PLAN"

say "profile embedding"
if [[ -n "$PROFILE_DESKTOP" ]]; then
    run cp "$PROFILE_DESKTOP" "$APP/Contents/embedded.provisionprofile"
    echo "embedded: Runne.app/Contents/embedded.provisionprofile"
fi
cred_dir="$(find "$APP/Contents" -maxdepth 5 -name 'RunneCredentialService.app' -type d 2>/dev/null | head -1 || true)"
if [[ -n "$cred_dir" && -n "$PROFILE_CRED" ]]; then
    run cp "$PROFILE_CRED" "$cred_dir/Contents/embedded.provisionprofile"
    echo "embedded: $cred_dir/Contents/embedded.provisionprofile"
fi

say "signing (inner-first)"
: > "$RESULTS"
while IFS=$'\t' read -r path expected ents member; do
    target="$APP_ROOT/$path"
    entitlements="$ENTS_DIR/${ents#macos/}"
    args=(--force --sign "$IDENTITY" --timestamp --options runtime)
    [[ -f "$entitlements" ]] && args+=(--entitlements "$entitlements")
    if printf '%s' "$(cat "$entitlements" 2>/dev/null || echo '')" | grep -q 'keychain-access-groups'; then
        needs_profile=0
        if [[ "$path" == *.app ]]; then
            if [[ -f "$target/Contents/embedded.provisionprofile" ]]; then
                needs_profile=1
            elif [[ "$DRY_RUN" -eq 1 && (("$path" == *"RunneCredentialService.app" && -n "$PROFILE_CRED") || ("$path" != *"RunneCredentialService.app" && -n "$PROFILE_DESKTOP")) ]]; then
                needs_profile=1  # dry-run: the flag-provided profile counts as embedded
            fi
        elif [[ "$ACCEPT_UNAUTHORIZED" -eq 1 ]]; then
            needs_profile=1
        fi
        if [[ "$needs_profile" -eq 0 ]]; then
            echo "REFUSED: $member claims keychain-access-groups without an embedded" >&2
            echo "provisioning profile (restricted entitlement, TN3125). Provide the" >&2
            echo "profile or pass --accept-unauthorized-restricted-claims explicitly." >&2
            exit 66
        fi
    fi
    echo "signing $member"
    run codesign "${args[@]}" "$target"
    if [[ "$DRY_RUN" -ne 1 ]]; then
        codesign --verify --strict "$target"
        printf '%s\t%s\t%s\n' "$member" "$(tree_sha "$target")" \
            "$(codesign -dvv "$target" 2>&1 | sed -n 's/.*CDHash=\([0-9a-f]*\).*/\1/p')" \
            >> "$RESULTS"
    fi
done < "$PLAN"

if [[ "$DRY_RUN" -ne 1 ]]; then
    python3 - "$MANIFEST" "$RESULTS" "$OUTPUT" <<'EOF'
import json, sys
manifest, results, out = sys.argv[1], sys.argv[2], sys.argv[3]
post = {}
for line in open(results):
    member, sha256, cdhash = line.rstrip("\n").split("\t")
    post[member] = {"sha256_post": sha256, "cdhash": cdhash}
json.dump({"identity_note": "verify CDHashes independently on the build host",
           "members": post}, open(out, "w"), indent=1)
print(f"return manifest: {out}")
EOF
    echo "transfer back: $APP, $OUTPUT"
fi
