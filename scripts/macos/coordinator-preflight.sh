#!/usr/bin/env bash
# Coordinator preflight for the Runne.app signing chain. STRICTLY READ-ONLY:
# no cp, no codesign, no keychain writes. Runs the COMPLETE check set BEFORE
# any mutating step of coordinator-sign.sh; every violation is reported and
# any violation exits non-zero.
#
# Checks:
#   1. manifest — fixed chain composition, order, uniqueness, path safety
#      (relative, no '..', no symlink escape from the artifact root),
#      sha256 format; entitlements bound to the verified manifest and
#      confined to the entitlements directory.
#   2. identity — parses to a team; present in the VALID list of
#      `security find-identity -p codesigning`.
#   3. profiles — for every bundle member whose entitlements claim the
#      RESTRICTED keychain-access-groups entitlement (TN3125): a profile is
#      provided, decodes, matches the identity team, covers the member's App
#      ID, is not expired, and its groups cover every claimed group.
#      File presence alone is NOT acceptance: contents are verified. NOTE:
#      `security cms -D` verifies the CMS container structure, not that Apple
#      signed the profile — origin trust is established at runtime, which is
#      the final authority.
#   4. standalone members (non-bundle executables) claiming restricted
#      entitlements are a violation by definition: a standalone executable
#      cannot embed a profile (TN3125). There is no bypass flag; see
#      DISTRIBUTED_SIGNING.md ("Proposal: app-like packaging").
#
# Usage:
#   coordinator-preflight.sh --identity "Developer ID Application: N (TEAM)" \
#     --app path/to/Runne.app --manifest manifest.json \
#     --entitlements-dir path/to/entitlements \
#     [--profile-desktop F] [--profile-credential-service F]
set -euo pipefail

VIOLATIONS=""
violated() { VIOLATIONS="${VIOLATIONS}  - $1"$'\n'; }

IDENTITY=""; APP=""; MANIFEST=""; ENTS_DIR=""; PROFILE_DESKTOP=""; PROFILE_CRED=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity) IDENTITY="$2"; shift 2 ;;
        --app) APP="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --entitlements-dir) ENTS_DIR="$2"; shift 2 ;;
        --profile-desktop) PROFILE_DESKTOP="$2"; shift 2 ;;
        --profile-credential-service) PROFILE_CRED="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done
[[ -n "$IDENTITY" && -n "$APP" && -n "$MANIFEST" && -n "$ENTS_DIR" ]] || { echo "missing required options" >&2; exit 64; }
[[ -d "$APP" && -f "$MANIFEST" && -d "$ENTS_DIR" ]] || { echo "missing input paths" >&2; exit 64; }

APP_ROOT="$(cd "$APP/.." && pwd)"

# 2. Identity: team token + presence among VALID identities (section-aware:
# "Matching identities" also lists expired/revoked certificates marked
# "(invalid)" — they must not pass). Pure bash: a nested quoted interpreter
# inside $() breaks the bash 3.2 parser used on stock macOS hosts.
TEAM="$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')"
identity_list="$(security find-identity -p codesigning 2>/dev/null || true)"
identity_verdict="NOT-VALID"
in_valid=0
while IFS= read -r line; do
    case "$line" in
        *"Valid identities only"*) in_valid=1 ;;
        *"Matching identities"*) in_valid=0 ;;
        *"(invalid)"*) ;;
        *"$IDENTITY"*) [[ "$in_valid" -eq 1 ]] && identity_verdict="OK" ;;
    esac
done <<< "$identity_list"
if [[ -z "$TEAM" ]]; then
    violated "identity does not contain a 10-character team token"
elif [[ "$identity_verdict" != "OK" ]]; then
    violated "identity not found among VALID codesigning identities"
fi

PY_MANIFEST="$(mktemp /tmp/runne-pf-manifest.XXXXXX)"
PY_ENTS="$(mktemp /tmp/runne-pf-ents.XXXXXX)"
PY_PROFILES="$(mktemp /tmp/runne-pf-profiles.XXXXXX)"
trap 'rm -f "$PY_MANIFEST" "$PY_ENTS" "$PY_PROFILES"' EXIT

# python payloads live in temp files: a heredoc inside "$( ... )" makes the
# stock macOS bash 3.2 parse the body as shell text (quote-state corruption).
cat > "$PY_MANIFEST" <<'PYEOF'
import json, os, sys

manifest_path, app_root = sys.argv[1], sys.argv[2]
problems = []
EXPECTED = [  # fixed composition and order (paths relative to artifact root)
    ("Runne.app/Contents/Library/Helpers/RunneCredentialService.app",
     "macos/credential-service.entitlements"),
    ("Runne.app/Contents/MacOS/runne", "macos/cli.entitlements"),
    ("Runne.app/Contents/MacOS/runned", "macos/daemon.entitlements"),
    ("Runne.app", "macos/desktop.entitlements"),
]
import re
ENT_FIELD = re.compile(r"^macos/[A-Za-z0-9._-]+\.entitlements$")
try:
    manifest = json.load(open(manifest_path))
except Exception as error:
    print(f"manifest unreadable: {error}")
    raise SystemExit(0)

members = manifest.get("members")
if not isinstance(members, list):
    problems.append("manifest has no members list")
else:
    paths = [member.get("path") for member in members]
    if len(set(paths)) != len(paths):
        problems.append("duplicate member paths in manifest")
    order = [(member.get("path"), member.get("entitlements")) for member in members]
    if order != EXPECTED:
        problems.append(f"member set/order differs from the fixed chain: {order} != {EXPECTED}")
    for member in members:
        path = member.get("path") or ""
        ent_field = member.get("entitlements") or ""
        if not ENT_FIELD.match(ent_field):
            problems.append(f"entitlements field must be macos/<name>.entitlements, got: {ent_field!r}")
        if os.path.isabs(path):
            problems.append(f"absolute member path: {path}")
        if ".." in path.split("/"):
            problems.append(f"parent traversal in member path: {path}")
        full = os.path.join(app_root, path)
        if os.path.realpath(full) != full and not os.path.realpath(full).startswith(os.path.realpath(app_root) + os.sep):
            problems.append(f"member escapes artifact root via symlink: {path}")
        if not os.path.exists(full):
            problems.append(f"member missing from artifact: {path}")
        digest = member.get("sha256_pre") or ""
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            problems.append(f"bad sha256_pre for {path}: {digest!r}")
if not problems:
    problems.append("OK")
print("\n".join(problems))
PYEOF
manifest_report="$(python3 - "$MANIFEST" "$APP_ROOT" < "$PY_MANIFEST")"
if [[ "$manifest_report" != "OK" ]]; then
    while IFS= read -r line; do violated "manifest: $line"; done <<< "$manifest_report"
fi

cat > "$PY_ENTS" <<'PYEOF'
import json, os, sys

manifest_path, ents_dir = sys.argv[1], sys.argv[2]
problems = []
try:
    manifest = json.load(open(manifest_path))
except Exception as error:
    raise SystemExit(0)  # already reported
ents_root = os.path.realpath(ents_dir)
for member in manifest.get("members", []):
    ent_field = member.get("entitlements") or ""
    rel = ent_field.split("/", 1)[1] if "/" in ent_field else ent_field
    if (not rel or "/" in rel.rstrip("/")) and os.path.basename(rel) != rel:
        problems.append(f"entitlements field not a bare staged file name: {ent_field}")
        continue
    full = os.path.join(ents_dir, rel)
    if not os.path.isfile(full):
        problems.append(f"entitlements missing for {member.get('member')}: {rel}")
        continue
    if not os.path.realpath(full).startswith(ents_root + os.sep):
        problems.append(f"entitlements escape the entitlements dir via symlink: {rel}")
print("\n".join(problems) if problems else "OK")
PYEOF
ents_report="$(python3 - "$MANIFEST" "$ENTS_DIR" < "$PY_ENTS")"
if [[ "$ents_report" != "OK" ]]; then
    while IFS= read -r line; do violated "entitlements: $line"; done <<< "$ents_report"
fi

cat > "$PY_PROFILES" <<'PYEOF'
import json, os, plistlib, subprocess, sys
from datetime import datetime, timezone

manifest_path, app_root, ents_dir, team, profile_desktop, profile_cred = sys.argv[1:7]
problems = []
try:
    manifest = json.load(open(manifest_path))
except Exception:
    raise SystemExit(0)

def decode_profile(path):
    # `security cms -D` decodes the CMS container into an XML plist; tests
    # may stub `security` to emit a plain plist fixture. plistlib parses the
    # result (json conversion cannot represent <date> values).
    raw = subprocess.run(["security", "cms", "-D", "-i", path],
                         capture_output=True)
    if raw.returncode != 0:
        return None
    try:
        return plistlib.loads(raw.stdout)
    except Exception:
        return None

def plist_json(path):
    with open(path, "rb") as handle:
        return plistlib.loads(handle.read())

def as_text(value):
    # plistlib decodes <date> into datetime; stringify anything non-scalar.
    if isinstance(value, datetime):
        return value.isoformat()
    return value

def group_covered(claimed, allowed):
    for candidate in allowed:
        if candidate == claimed:
            return True
        if candidate.endswith("*") and claimed.startswith(candidate[:-1]):
            return True
    return False

for member in manifest.get("members", []):
    path = member.get("path") or ""
    ent_field = member.get("entitlements") or ""
    full = os.path.join(ents_dir, ent_field.split("/", 1)[1] if "/" in ent_field else ent_field)
    if not os.path.isfile(full):
        continue  # already reported
    try:
        claims = plist_json(full)
    except Exception:
        problems.append(f"entitlements plist unparsable: {ent_field}")
        continue
    claimed_groups = [str(as_text(g)) for g in (claims.get("keychain-access-groups") or [])]
    is_bundle = path.endswith(".app")
    if not claimed_groups:
        continue
    if not is_bundle:
        problems.append(
            f"standalone executable claims restricted keychain-access-groups "
            f"and cannot embed a profile (TN3125): {path}; wrap it app-like or "
            f"drop the claim (see DISTRIBUTED_SIGNING proposal)")
        continue
    profile = profile_desktop if path == "Runne.app" else (
        profile_cred if "RunneCredentialService" in path else None)
    if not profile:
        problems.append(f"no provisioning profile provided for {path} "
                        f"(claims {claimed_groups})")
        continue
    if not os.path.isfile(profile):
        problems.append(f"provisioning profile file missing: {profile}")
        continue
    decoded = decode_profile(profile)
    if decoded is None:
        problems.append(f"provisioning profile does not decode (not a CMS "
                        f"container or unreadable): {profile}")
        continue
    expiration = as_text(decoded.get("ExpirationDate"))
    if expiration:
        try:
            # plistlib decodes <date> as naive UTC; compare against naive now.
            moment = datetime.fromisoformat(str(expiration).replace("Z", "+00:00")).replace(tzinfo=None)
            if moment <= datetime.now(timezone.utc).replace(tzinfo=None):
                problems.append(f"provisioning profile EXPIRED {expiration}: {profile}")
        except ValueError:
            problems.append(f"provisioning profile expiration unparsable: {expiration}")
    profile_teams = [str(t) for t in (decoded.get("TeamIdentifier") or [])]
    if team and team not in profile_teams:
        problems.append(f"profile team {profile_teams} does not match the "
                        f"signing identity team {team}: {profile}")
    entitlements_block = decoded.get("Entitlements", {})
    allowed_groups = [str(as_text(g)) for g in (entitlements_block.get("keychain-access-groups") or [])]
    for claimed in claimed_groups:
        if not group_covered(claimed, allowed_groups):
            problems.append(f"profile does not authorize claimed group "
                            f"{claimed} for {path}; profile allows {allowed_groups}")
    app_id = as_text(entitlements_block.get("application-identifier", ""))
    # bundle_id comes from the ARTIFACT Info.plist, never from the manifest.
    info_plist = os.path.join(app_root, path, "Contents", "Info.plist")
    bundle_id = None
    if os.path.isfile(info_plist):
        try:
            with open(info_plist, "rb") as handle:
                bundle_id = str(plistlib.load(handle).get("CFBundleIdentifier", "")) or None
        except Exception:
            problems.append(f"unreadable Info.plist for {path}")
    declared = member.get("bundle_id")
    if bundle_id and declared and declared != bundle_id:
        problems.append(f"manifest bundle_id {declared} does not match the "
                        f"artifact bundle id {bundle_id} for {path}")
    if app_id and bundle_id and not (
            app_id == f"{team}.{bundle_id}"
            or (app_id.endswith("*") and bundle_id.startswith(app_id[:-1]))):
        problems.append(f"profile App ID {app_id} does not cover bundle id "
                        f"{bundle_id} for {path}")
print("\n".join(problems) if problems else "OK")
PYEOF
profile_report="$(python3 - "$MANIFEST" "$APP_ROOT" "$ENTS_DIR" "$TEAM" "$PROFILE_DESKTOP" "$PROFILE_CRED" < "$PY_PROFILES")"
if [[ "$profile_report" != "OK" ]]; then
    while IFS= read -r line; do violated "profile: $line"; done <<< "$profile_report"
fi

if [[ -n "$VIOLATIONS" ]]; then
    echo "PREFLIGHT FAILED — artifact must stay unchanged:" >&2
    printf '%s' "$VIOLATIONS" >&2
    exit 1
fi
echo "preflight: all checks passed"
