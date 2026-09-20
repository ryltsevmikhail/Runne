#!/usr/bin/env bash
# Build-side (Mac mini): generate the signing manifest for a Runne.app
# artifact. The manifest lists every member of the signing chain with its
# bundle id, the repository entitlements file that authorizes its claims,
# and the pre-sign SHA-256. The coordinator uses it to verify the transfer
# and to sign inner-first without guessing.
#
# Read-only over the artifact; writes only the manifest file given as argv 2.
#
# Usage: scripts/macos/prepare-signing-manifest.sh path/to/Runne.app out/manifest.json
set -euo pipefail

APP="${1:-}"
OUT="${2:-}"
if [[ -z "$APP" || ! -d "$APP" || -z "$OUT" ]]; then
    echo "usage: $0 path/to/Runne.app out/manifest.json" >&2
    exit 64
fi
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ENTS="$REPO/apps/desktop/src-tauri/macos"

CRED_SERVICE="$(find "$APP/Contents" -maxdepth 5 -name 'RunneCredentialService.app' -type d 2>/dev/null | head -1 || true)"

python3 - "$APP" "$OUT" "$ENTS" "$CRED_SERVICE" <<'EOF'
import hashlib, json, os, subprocess, sys

app, out, ents, cred = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def sha256(path):
    digest = hashlib.sha256()
    if os.path.isdir(path):
        for root, dirs, files in sorted(os.walk(path)):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                digest.update(os.path.relpath(full, path).encode())
                with open(full, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1 << 20), b""):
                        digest.update(chunk)
        return digest.hexdigest()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def bundle_id(plist):
    try:
        return subprocess.check_output(
            ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleIdentifier", plist],
            text=True).strip()
    except subprocess.CalledProcessError:
        return None

members = [
    {"path": "Runne.app/Contents/MacOS/runne", "member": "runne",
     "bundle_id": None, "entitlements": "macos/cli.entitlements",
     "restricted_entitlement": True},
    {"path": "Runne.app/Contents/MacOS/runned", "member": "runned",
     "bundle_id": None, "entitlements": "macos/daemon.entitlements",
     "restricted_entitlement": True},
    {"path": "Runne.app", "member": "Runne.app (outer bundle)",
     "bundle_id": bundle_id(os.path.join(app, "Contents", "Info.plist")),
     "entitlements": "macos/desktop.entitlements",
     "restricted_entitlement": True},
]
if cred:
    rel = os.path.relpath(cred, app)
    members.insert(0, {
        "path": f"Runne.app/{rel}", "member": "RunneCredentialService.app",
        "bundle_id": bundle_id(os.path.join(cred, "Contents", "Info.plist")),
        "entitlements": "macos/credential-service.entitlements",
        "restricted_entitlement": True,
    })

for member in members:
    target = member["path"] if member["path"] != "Runne.app" else "."
    full = os.path.normpath(os.path.join(app, "..", member["path"]))
    member["sha256_pre"] = sha256(full)

manifest = {
    "artifact_root": os.path.basename(os.path.normpath(app)),
    "sign_order": [member["path"] for member in members],
    "members": members,
    "profile_embedding": {
        "Runne.app": "Runne.app/Contents/embedded.provisionprofile (profile must authorize com.runne.desktop + keychain-access-groups)",
        "RunneCredentialService.app": "embedded into the nested .app bundle (profile must authorize its bundle id)",
        "runne/runned": "standalone executables cannot embed a profile (TN3125); restricted claims on them need the documented app-like wrap or must be dropped before signing",
    },
    "notes": [
        "pre-sign SHA-256 values: verify on the coordinator before signing",
        "signing changes every member: return post-sign SHA-256 and CDHashes for transfer verification",
        "sign inner-first in 'sign_order'; outer bundle last with --options runtime --timestamp",
    ],
}
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
with open(out, "w") as handle:
    json.dump(manifest, handle, indent=1)
print(f"manifest written: {out} ({len(members)} members)")
EOF
