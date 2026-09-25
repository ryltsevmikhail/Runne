# Manifest violations.
# Manifest violations.
make_manifest
python3 -c "
import json
m = json.load(open('$WORK/manifest.json'))
m['members'][2]['path'] = '/etc/passwd'
json.dump(m, open('$WORK/manifest.json', 'w'))"
expect_refusal "absolute member path" "absolute member path" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

make_manifest
python3 -c "
import json
m = json.load(open('$WORK/manifest.json'))
m['members'][2]['path'] = 'Runne.app/Contents/../../escaped'
json.dump(m, open('$WORK/manifest.json', 'w'))"
expect_refusal "parent traversal in member path" "parent traversal" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

make_manifest
python3 -c "
import json
m = json.load(open('$WORK/manifest.json'))
m['members'].append(dict(m['members'][1]))
json.dump(m, open('$WORK/manifest.json', 'w'))"
expect_refusal "duplicate member" "duplicate member paths" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

make_manifest
python3 -c "
import json
m = json.load(open('$WORK/manifest.json'))
del m['members'][1]
json.dump(m, open('$WORK/manifest.json', 'w'))"
expect_refusal "missing member breaks fixed chain" "fixed chain" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

# Entitlements violations.
point_cli_at() {
    python3 -c "
import json
m = json.load(open('$WORK/manifest.json'))
m['members'][1]['entitlements'] = 'macos/$1'
json.dump(m, open('$WORK/manifest.json', 'w'))"
}
printf 'secret' > "$WORK/secret-outside.entitlements"
ln -sf "$WORK/secret-outside.entitlements" "$WORK/entitlements/escaped-link.entitlements"
point_cli_at "escaped-link.entitlements"
expect_refusal "entitlements symlink escape" \
    "escape the entitlements dir" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"
point_cli_at "../../desktop.entitlements"
expect_refusal "traversal in entitlements field" \
    "entitlements field must be macos/" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"
rm -f "$WORK/entitlements/escaped-link.entitlements" "$WORK/secret-outside.entitlements"
printf '%s' "$(claim_free com.runne.cli)" > "$WORK/entitlements/cli.entitlements"
printf '%s' "$(claim_free com.runne.daemon)" > "$WORK/entitlements/daemon.entitlements"

make_manifest "missing.entitlements" "daemon.entitlements" "desktop.entitlements" "credential-service.entitlements"
expect_refusal "entitlements file missing" "entitlements missing" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

# Standalone claiming restricted entitlements: refused even WITH profiles offered.
printf '%s' "$(ent com.runne.cli)" > "$WORK/entitlements/cli.entitlements"
printf '%s' "$(ent com.runne.daemon)" > "$WORK/entitlements/daemon.entitlements"
make_manifest
expect_refusal "standalone member with restricted claims" "standalone executable claims restricted" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

# Profile violations (drop the standalone conflict first: claim-free plists so
# the profile checks for the bundles are what fires).
printf '%s' "$(plist '<key>com.apple.application-identifier</key><string>AAAABBBBCC.com.runne.cli</string>')" > "$WORK/entitlements/cli.entitlements"
printf '%s' "$(plist '<key>com.apple.application-identifier</key><string>AAAABBBBCC.com.runne.daemon</string>')" > "$WORK/entitlements/daemon.entitlements"

make_manifest
expect_refusal "profiles not provided" "missing required options" --entitlements-dir "$WORK/entitlements"

printf '%s' "$(profile_fixture "$PAST" com.runne.desktop)" > "$WORK/profiles/desktop-expired.provisionprofile"
make_manifest
expect_refusal "expired profile" "EXPIRED" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop-expired.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

printf '%s' "$(profile_fixture "$FUTURE" com.runne.credential-service)" > "$WORK/profiles/desktop-wrongapp.provisionprofile"
make_manifest
expect_refusal "profile App ID mismatch" "does not cover bundle id" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop-wrongapp.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

printf '%s' "$(profile_fixture "$FUTURE" com.runne.desktop DDDDCCCCBBBB)" > "$WORK/profiles/desktop-wrongteam.provisionprofile"
make_manifest
expect_refusal "profile team mismatch" "does not match the " --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop-wrongteam.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

plist_groups() { plist "<key>TeamIdentifier</key><array><string>AAAABBBBCC</string></array><key>ExpirationDate</key><date>$1</date><key>Entitlements</key><dict><key>application-identifier</key><string>AAAABBBBCC.$2</string><key>keychain-access-groups</key><array><string>AAAABBBBCC.other</string></array></dict>"; }
printf '%s' "$(plist_groups "$FUTURE" com.runne.desktop)" > "$WORK/profiles/desktop-nogroups.provisionprofile"
make_manifest
expect_refusal "profile groups do not cover claims" "does not authorize claimed group" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop-nogroups.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"

printf 'not a profile' > "$WORK/profiles/desktop-garbage.provisionprofile"
make_manifest
expect_refusal "profile does not decode" "does not decode" --entitlements-dir "$WORK/entitlements" \
    --profile-desktop "$WORK/profiles/desktop-garbage.provisionprofile" \
    --profile-credential-service "$WORK/profiles/credential-service.provisionprofile"
