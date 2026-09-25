#!/usr/bin/env bash
# Refusal tests for coordinator-preflight.sh / coordinator-sign.sh.
# Every refusal must (a) exit non-zero, (b) happen before any mutation —
# proven by hashing the artifact tree before/after, (c) mention the cause.
#
# `security` is stubbed via PATH: `cms -D` emits the file verbatim when it is
# a plain plist fixture (production runs use the real CMS decoder; the stub
# only stands in for the decode step in tests). The stub also provides a
# find-identity listing containing the test identity.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"   # scripts/macos
WORK="$(mktemp -d /tmp/runne-preflight-tests.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

failures=0
note() { printf '%s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*" >&2; failures=$((failures + 1)); }

mkdir -p "$WORK/bin"
cat > "$WORK/bin/security" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "cms" && "${2:-}" == "-D" ]]; then
    file="${@: -1}"; file="${file#-i }"
    if head -c 5 "$file" | grep -q '<?xml'; then cat "$file"; else exit 1; fi
    exit 0
fi
if [[ "${1:-}" == "find-identity" ]]; then
    printf 'Policy: Code Signing\n  Matching identities\n'
    printf '  1) abcdef0123456789abcdef0123456789abcdef01 "Developer ID Application: Tester (AAAABBBBCC)"\n'
    printf '  2) 1234567890abcdef1234567890abcdef12345678 "Developer ID Application: Owner (758F9Z45SR)"\n'
    printf '     2 identities found\n  Valid identities only\n'
    printf '  1) abcdef0123456789abcdef0123456789abcdef01 "Developer ID Application: Tester (AAAABBBBCC)"\n'
    printf '  2) 1234567890abcdef1234567890abcdef12345678 "Developer ID Application: Owner (758F9Z45SR)"\n'
    printf '     2 valid identities found\n'
    exit 0
fi
exit 1
STUB
chmod +x "$WORK/bin/security"
IDENTITY="Developer ID Application: Tester (AAAABBBBCC)"
export PATH="$WORK/bin:$PATH"

# Fixture artifact: Runne.app skeleton + staged credential-service.
APP="$WORK/Runne.app"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS" "$APP/Contents/Resources"
printf 'main' > "$APP/Contents/MacOS/runne-desktop"; printf 'cli' > "$APP/Contents/MacOS/runne"
printf 'daemon' > "$APP/Contents/MacOS/runned"; printf 'helper' > "$APP/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string com.runne.desktop' "$APP/Contents/Info" 2>/dev/null || :; mv "$APP/Contents/Info" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string com.runne.credential-service' "$APP/Contents/Library/Helpers/RunneCredentialService.app/Contents/Info" 2>/dev/null || :; mv "$APP/Contents/Library/Helpers/RunneCredentialService.app/Contents/Info" "$APP/Contents/Library/Helpers/RunneCredentialService.app/Contents/Info.plist"
mkdir -p "$WORK/entitlements" "$WORK/profiles"

plist() { printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>%s</dict></plist>' "$1"; }
ent() { plist "<key>com.apple.application-identifier</key><string>AAAABBBBCC.$1</string><key>keychain-access-groups</key><array><string>AAAABBBBCC.$1</string></array>${2:-}"; }

printf '%s' "$(ent com.runne.credential-service)" > "$WORK/entitlements/credential-service.entitlements"
# Resolvable model: standalone members do NOT claim restricted entitlements
# (they cannot embed a profile — TN3125; see DISTRIBUTED_SIGNING proposal).
claim_free() { printf '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.application-identifier</key><string>AAAABBBBCC.%s</string></dict></plist>' "$1"; }
printf '%s' "$(claim_free com.runne.cli)" > "$WORK/entitlements/cli.entitlements"
printf '%s' "$(claim_free com.runne.daemon)" > "$WORK/entitlements/daemon.entitlements"
printf '%s' "$(ent com.runne.desktop)" > "$WORK/entitlements/desktop.entitlements"

FUTURE="$(date -u -v+1y '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+1 year' '+%Y-%m-%dT%H:%M:%SZ')"
PAST="$(date -u -v-1y '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '-1 year' '+%Y-%m-%dT%H:%M:%SZ')"
profile_fixture() { # $1 expiration, $2 app-id suffix, $3 team prefix
    plist "<key>TeamIdentifier</key><array><string>${3:-AAAABBBBCC}</string></array><key>ExpirationDate</key><date>$1</date><key>Entitlements</key><dict><key>application-identifier</key><string>${3:-AAAABBBBCC}.$2</string><key>keychain-access-groups</key><array><string>${3:-AAAABBBBCC}.$2</string></array></dict>"
}
printf '%s' "$(profile_fixture "$FUTURE" com.runne.desktop)" > "$WORK/profiles/desktop.provisionprofile"
printf '%s' "$(profile_fixture "$FUTURE" com.runne.credential-service)" > "$WORK/profiles/credential-service.provisionprofile"

hash_tree() { find "$APP" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'; }

# Build a manifest with pre-sign hashes; $@ overrides member entitlements list.
make_manifest() {
    python3 - "$APP" "$WORK/manifest.json" "$@" <<'EOF'
import hashlib, json, os, sys
app, out = sys.argv[1], sys.argv[2]
overrides = sys.argv[3:]
def tree(path):
    digest = hashlib.sha256()
    if os.path.isfile(path):
        digest.update(open(path, "rb").read()); return digest.hexdigest()
    for base, dirs, files in sorted(os.walk(path)):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(base, name)
            digest.update(os.path.relpath(full, path).encode())
            digest.update(open(full, "rb").read())
    return digest.hexdigest()
members = [
    {"path": "Runne.app/Contents/Library/Helpers/RunneCredentialService.app",
     "member": "RunneCredentialService.app", "bundle_id": "com.runne.credential-service",
     "entitlements": "macos/credential-service.entitlements"},
    {"path": "Runne.app/Contents/MacOS/runne", "member": "runne", "bundle_id": None,
     "entitlements": "macos/cli.entitlements"},
    {"path": "Runne.app/Contents/MacOS/runned", "member": "runned", "bundle_id": None,
     "entitlements": "macos/daemon.entitlements"},
    {"path": "Runne.app", "member": "Runne.app (outer bundle)",
     "bundle_id": "com.runne.desktop", "entitlements": "macos/desktop.entitlements"},
]
for member in members:
    if overrides:
        member["entitlements"] = overrides.pop(0)
    member["sha256_pre"] = tree(os.path.join(app, "..", member["path"]))
json.dump({"members": members}, open(out, "w"), indent=1)
EOF
}

expect_refusal() {
    local case_name="$1" cause="$2"; shift 2
    local before after rc
    before="$(hash_tree)"
    OUT="$("$HERE/coordinator-sign.sh" --dry-run --identity "$IDENTITY" --app "$APP" --manifest "$WORK/manifest.json" "$@" 2>&1)"; rc=$?
    after="$(hash_tree)"
    if [[ "$rc" -eq 0 ]]; then fail "$case_name: expected non-zero exit, got 0"; fi
    if [[ "$before" != "$after" ]]; then fail "$case_name: artifact mutated by a refusal"; fi
    if [[ "$OUT" == *"== signing (inner-first)"* || "$OUT" == *"DRY-RUN: codesign"* ]]; then
        fail "$case_name: reached the signing phase"
    fi
    if [[ "$OUT" != *"$cause"* ]]; then
        fail "$case_name: expected cause '$cause' in output; actual:"
        printf '%s\n' "$OUT" | sed 's/^/     | /' >&2
    fi
    note "ok   refusal: $case_name (rc=$rc)"
}

PREFLIGHT="$HERE/coordinator-preflight.sh"
pre() { "$PREFLIGHT" --identity "$IDENTITY" --app "$APP" --manifest "$WORK/manifest.json" "$@"; }

# Happy path: full sign dry-run passes preflight and prints no real mutation.
make_manifest
if pre --entitlements-dir "$WORK/entitlements" \
      --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
      --profile-credential-service "$WORK/profiles/credential-service.provisionprofile" >/dev/null 2>&1; then
    note "ok   preflight happy path passes"
else
    fail "preflight happy path should pass; violations:"
    pre --entitlements-dir "$WORK/entitlements" \
        --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
        --profile-credential-service "$WORK/profiles/credential-service.provisionprofile" 2>&1 \
        | sed 's/^/     /' >&2
fi
OUT="$(PATH="$PATH" "$HERE/coordinator-sign.sh" --dry-run --identity "$IDENTITY" --app "$APP" \
    --manifest "$WORK/manifest.json" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile" 2>&1)"
rc=$?
if [[ "$rc" -ne 0 ]]; then fail "happy-path dry-run exited $rc: $OUT"; fi
if [[ "$OUT" == *"PREFLIGHT FAILED"* ]]; then fail "happy-path dry-run reported violations"; fi

# End-to-end: the REAL repository prepare script and the REAL repo
# entitlements files produce the manifest + verbatim staged copies;
# the standalone-claims refusal is the expected current-contract outcome.
e2e_root="$WORK/e2e"; e2e_app="$e2e_root/Runne.app"
mkdir -p "$e2e_app/Contents/MacOS" "$e2e_app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS"
printf 'main' > "$e2e_app/Contents/MacOS/runne-desktop"; printf 'cli' > "$e2e_app/Contents/MacOS/runne"
printf 'daemon' > "$e2e_app/Contents/MacOS/runned"
printf 'helper' > "$e2e_app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service"
printf '%s' "$(plist '<key>CFBundleIdentifier</key><string>com.runne.desktop</string>')" > "$e2e_app/Contents/Info.plist"
printf '%s' "$(plist '<key>CFBundleIdentifier</key><string>com.runne.credential-service</string>')" > "$e2e_app/Contents/Library/Helpers/RunneCredentialService.app/Contents/Info.plist"
printf '%s' "$(profile_fixture "$FUTURE" com.runne.desktop 758F9Z45SR)" > "$WORK/profiles/e2e-desktop.provisionprofile"
printf '%s' "$(profile_fixture "$FUTURE" com.runne.credential-service 758F9Z45SR)" > "$WORK/profiles/e2e-credential-service.provisionprofile"
E2E_IDENTITY="Developer ID Application: Owner (758F9Z45SR)"
"$HERE/prepare-signing-manifest.sh" "$e2e_app" "$WORK/e2e/manifest.json" >/dev/null 2>&1
E2E_OUT="$("$HERE/coordinator-preflight.sh" --identity "$E2E_IDENTITY" --app "$e2e_app" \
    --manifest "$WORK/e2e/manifest.json" --entitlements-dir "$WORK/e2e/entitlements" \
    --profile-desktop "$WORK/profiles/e2e-desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/e2e-credential-service.provisionprofile" 2>&1)"; E2E_RC=$?
if [[ "$E2E_RC" -ne 0 && "$E2E_OUT" == *"standalone executable claims restricted"* \
      && "$E2E_OUT" == *"Runne.app/Contents/MacOS/runne"* \
      && "$E2E_OUT" == *"Runne.app/Contents/MacOS/runned"* ]]; then
    note "ok   end-to-end: real repo entitlements refused with the explicit standalone-claims message (current contract)"
else
    fail "end-to-end: expected the explicit standalone-claims refusal on real repo entitlements"
    printf '%s\n' "$E2E_OUT" | sed 's/^/     | /' >&2
fi

# Transfer completeness: unpack ONLY the documented archive into a clean
# directory (no repository checkout) and run the documented preflight there.
mkdir -p "$WORK/transfer"
cp -R "$e2e_app" "$WORK/transfer/Runne.app"
cp "$WORK/e2e/manifest.json" "$WORK/transfer/manifest.json"
cp -R "$WORK/e2e/entitlements" "$WORK/transfer/entitlements"
cp "$HERE/coordinator-sign.sh" "$HERE/coordinator-preflight.sh" "$WORK/transfer/"
tar -C "$WORK/transfer" -czf "$WORK/runne-artifact.tar.gz" \
    "$(basename "$e2e_app")" manifest.json entitlements coordinator-sign.sh coordinator-preflight.sh
rm -rf "$WORK/unpacked" && mkdir -p "$WORK/unpacked"
tar -C "$WORK/unpacked" -xzf "$WORK/runne-artifact.tar.gz"
for required in Runne.app manifest.json entitlements coordinator-sign.sh coordinator-preflight.sh; do
    [[ -e "$WORK/unpacked/$required" ]] || fail "transfer package missing: $required"
done
note "ok   transfer package inventory complete"
TC_OUT="$("$WORK/unpacked/coordinator-sign.sh" --dry-run --identity "$E2E_IDENTITY" \
    --app "$WORK/unpacked/Runne.app" --manifest "$WORK/unpacked/manifest.json" \
    --entitlements-dir "$WORK/unpacked/entitlements" \
    --profile-desktop "$WORK/profiles/e2e-desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/e2e-credential-service.provisionprofile" 2>&1)"; TC_RC=$?
if [[ "$TC_RC" -ne 0 && "$TC_OUT" == *"standalone executable claims restricted"* \
      && "$TC_OUT" != *"No such file"* && "$TC_OUT" != *"command not found"* ]]; then
    note "ok   documented preflight runs standalone from the unpacked package (refuses on the current contract)"
else
    fail "documented preflight did not run standalone from the unpacked package"
    printf '%s\n' "$TC_OUT" | sed 's/^/     | /' >&2
fi

source "$HERE/tests/manifest-refusal-cases.sh"
if [[ "$failures" -eq 0 ]]; then
    echo "all refusal tests passed"
    exit 0
fi
echo "$failures refusal test(s) failed" >&2
exit 1
