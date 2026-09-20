#!/usr/bin/env bash
# Coordinator-side (Mac with the signing identity): run the FULL read-only
# preflight, embed Developer ID provisioning profiles, sign the chain
# inner-first, and emit a return manifest with post-sign SHA-256 values and
# CDHashes. The private key never leaves the coordinator host.
#
# There is NO bypass for restricted entitlements: standalone executables
# claiming keychain-access-groups are refused by preflight (TN3125) — see
# DISTRIBUTED_SIGNING.md, "Proposal: app-like packaging".
#
# Usage:
#   coordinator-sign.sh --identity "Developer ID Application: NAME (TEAM)" \
#     --app path/to/Runne.app --manifest manifest.json \
#     --entitlements-dir path/to/entitlements \
#     --profile-desktop desktop.provisionprofile \
#     [--profile-credential-service credential-service.provisionprofile] \
#     [--output return-manifest.json] [--dry-run]
set -euo pipefail

IDENTITY=""; APP=""; MANIFEST=""; ENTS_DIR=""; PROFILE_DESKTOP=""; PROFILE_CRED=""
OUTPUT="return-manifest.json"; DRY_RUN=0

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
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done
[[ -n "$IDENTITY" && -n "$APP" && -n "$MANIFEST" && -n "$ENTS_DIR" && -n "$PROFILE_DESKTOP" && -n "$PROFILE_CRED" ]] || { echo "missing required options (--profile-desktop and --profile-credential-service are required)" >&2; exit 64; }
[[ -d "$APP" && -f "$MANIFEST" && -d "$ENTS_DIR" && -f "$PROFILE_DESKTOP" && -f "$PROFILE_CRED" ]] || { echo "missing input paths" >&2; exit 64; }

HERE="$(cd "$(dirname "$0")" && pwd)"
PLAN="$(mktemp /tmp/runne-coordinator-plan.XXXXXX)"
RESULTS="$(mktemp /tmp/runne-coordinator-result.XXXXXX)"
MANIFEST_SNAPSHOT="$(mktemp /tmp/runne-coordinator-manifest.XXXXXX)"
trap 'rm -f "$PLAN" "$RESULTS" "$MANIFEST_SNAPSHOT"' EXIT
# Freeze the manifest once: preflight and the signing plan must observe the
# exact same bytes even if the transfer directory changes underneath.
cp "$MANIFEST" "$MANIFEST_SNAPSHOT"

say() { printf '\n== %s\n' "$1"; }
run() { if [[ "$DRY_RUN" -eq 1 ]]; then echo "DRY-RUN: $*"; else "$@"; fi; }

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

say "preflight (read-only; every check runs before any mutation)"
"$HERE/coordinator-preflight.sh" \
    --identity "$IDENTITY" --app "$APP" --manifest "$MANIFEST_SNAPSHOT" \
    --entitlements-dir "$ENTS_DIR" \
    ${PROFILE_DESKTOP:+--profile-desktop "$PROFILE_DESKTOP"} \
    ${PROFILE_CRED:+--profile-credential-service "$PROFILE_CRED"}

python3 - "$MANIFEST_SNAPSHOT" > "$PLAN" <<'EOF'
import json, sys
manifest = json.load(open(sys.argv[1]))
for member in manifest["members"]:
    print(f"{member['path']}\t{member['sha256_pre']}\t{member['entitlements']}\t{member['member']}")
EOF

APP_ROOT="$(cd "$APP/.." && pwd)"
say "transfer verification (pre-sign SHA-256 from manifest)"
while IFS=$'\t' read -r path expected ents member; do
    actual="$(tree_sha "$APP_ROOT/$path")"
    if [[ "$actual" != "$expected" ]]; then
        echo "MISMATCH for $member: manifest=$expected actual=$actual" >&2
        exit 65
    fi
    echo "ok   $member"
done < "$PLAN"

say "profile embedding"
if [[ -n "$PROFILE_DESKTOP" ]]; then
    run cp "$PROFILE_DESKTOP" "$APP/Contents/embedded.provisionprofile"
    echo "embedded: Runne.app/Contents/embedded.provisionprofile"
fi
cred_dir="$(find "$APP/Contents" -maxdepth 5 -name 'RunneCredentialService.app' -type d 2>/dev/null | head -1 || true)"
if [[ -n "$cred_dir" && -n "$PROFILE_CRED" ]]; then
    run cp "$PROFILE_CRED" "$cred_dir/Contents/embedded.provisionprofile"
    echo "embedded: $(basename "$cred_dir")/Contents/embedded.provisionprofile"
fi

say "signing (inner-first)"
while IFS=$'\t' read -r path expected ents member; do
    target="$APP_ROOT/$path"
    entitlements="$ENTS_DIR/${ents#macos/}"
    echo "signing $member"
    run codesign --force --sign "$IDENTITY" --timestamp --options runtime \
        --entitlements "$entitlements" "$target"
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
json.dump({"members": post}, open(out, "w"), indent=1)
print(f"return manifest: {out}")
EOF
    bundle_dir="$(cd "$APP/.." && pwd)"
    tar -C "$bundle_dir" -czf "$bundle_dir/runne-signed.tar.gz" "$(basename "$APP")" "$(basename "$OUTPUT")"
    echo "transfer back: $bundle_dir/runne-signed.tar.gz"
    shasum -a 256 "$bundle_dir/runne-signed.tar.gz" | awk '{print "sha256: " $1}'
fi
