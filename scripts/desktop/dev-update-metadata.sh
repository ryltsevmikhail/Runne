#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/desktop/dev-update-metadata.sh

End-to-end dev installed-release metadata chain for the staged dev bundle
(target/dev-bundle/Runne.app, assembled by scripts/desktop/dev-signed-run.sh):

  1. ensure target/debug/runne-update-metadata-producer is built and
     Developer ID signed as com.runne.update-metadata-producer
  2. ensure the dev_enrollment_tuple example harness is built
  3. package the bundle into a reused dev artifact archive and measure it
  4. run the harness to produce the NativeEnrollmentTupleV3 JSON
  5. build the UpdateMetadataDraft JSON from the tuple + staged
     release-candidate-binding.json + tauri.conf.json version
  6. unlock the dev keychain and issue threshold-signed UpdateMetadataV2
  7. seed the installed-update journals
     (<bundled-runtime>/updates/{install-state,trust-state,installed-metadata}.json.1.json)
     so the dev desktop/daemon (built with the DEV trust root) can admit
     native enrollment

Prerequisites: target/dev-metadata/{update-root.env,keychain-pass,
dev-trust-manifest.json} (created by the dev keyset initialization step)
and an assembled signed bundle.

Exit codes:
  0  success
  1  any step failed (fail closed)
  2  usage error
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

bundle="target/dev-bundle/Runne.app"
metadata_dir="target/dev-metadata"
# Issuer output must be absolute (publish_json rejects relative paths).
out_dir="$repo_root/$metadata_dir/update"
artifact_dir="$repo_root/$metadata_dir/artifact"
staged_binding_src="apps/desktop/src-tauri/macos/native-enrollment/staged/release-candidate-binding.json"
tauri_conf="apps/desktop/src-tauri/tauri.conf.json"
keychain="$HOME/Library/Keychains/runne-dev-update.keychain-db"

fail() { echo "error: $*" >&2; exit 1; }

for required in "$bundle" "$metadata_dir/update-root.env" "$metadata_dir/keychain-pass" \
  "$metadata_dir/dev-trust-manifest.json" "$tauri_conf" "$staged_binding_src" "$keychain"; do
  [[ -e "$required" ]] || fail "missing required input: $required"
done
[[ -f "$HOME/Library/Keychains/runne-dev-update.keychain-db" ]] || fail "missing dev keychain"

rm -rf "$out_dir"
mkdir -p "$out_dir" "$artifact_dir"

# The compiled daemon policy (RUNNE_UPDATE_* set by dev-signed-run.sh at build
# time) must equal the staged binding and this script's channel/version choice.
profile_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["profileId"])' "$staged_binding_src")
binding_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$staged_binding_src")
channel="dev"
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$tauri_conf")
[[ "$version" == "$binding_version" ]] || fail "tauri.conf.json version $version != staged binding version $binding_version"

# ── 1. producer binary: build + Developer ID sign with the fixed identifier ──
producer="target/debug/runne-update-metadata-producer"
if [[ ! -f "$producer" ]]; then
  cargo build -p runne-update-metadata-producer
fi
identity="${RUNNE_MACOS_SIGNING_IDENTITY:-}"
if [[ -z "$identity" ]]; then
  identity=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk '/Developer ID Application/ { print $2; exit }')
  [[ -n "$identity" ]] || fail "no valid Developer ID Application identity found"
fi
codesign --sign "$identity" --force --options runtime --timestamp \
  --identifier com.runne.update-metadata-producer "$producer"
codesign --verify --strict "$producer"
producer_display="$(codesign --display --verbose=2 "$producer" 2>&1)" || true
grep -q "Identifier=com.runne.update-metadata-producer" <<<"$producer_display" \
  || fail "producer binary identifier is not com.runne.update-metadata-producer"

# ── 2. example harness binary ────────────────────────────────────────────────
harness="target/debug/examples/dev_enrollment_tuple"
if [[ ! -f "$harness" ]]; then
  cargo build -p runne-platform-desktop --example dev_enrollment_tuple
fi
[[ -f "$harness" ]] || fail "example harness binary not found: $harness"

# ── 3. dev artifact archive (reused while the bundle tree is unchanged) ─────
bundle_fingerprint() {
  find "$bundle" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'
}
artifact="$artifact_dir/Runne-$version-dev.zip"
fingerprint="$(bundle_fingerprint)"
if [[ ! -f "$artifact" || "$(cat "$artifact_dir/bundle.fingerprint" 2>/dev/null)" != "$fingerprint" ]]; then
  rm -f "$artifact"
  ditto -c -k --keepParent "$bundle" "$artifact"
  printf '%s' "$fingerprint" > "$artifact_dir/bundle.fingerprint"
fi
artifact_sha256=$(shasum -a 256 "$artifact" | awk '{print $1}')
artifact_size=$(stat -f %z "$artifact")
# Strict verification requires HTTPS and a .dmg-shaped macos artifact URL;
# the archive above is only the dev digest source for that placeholder URL.
artifact_url="https://updates.dev.runne.invalid/dev/Runne-$version-macos-arm64.dmg"

# ── 4. produce the tuple from the signed bundle ──────────────────────────────
abs_bundle="$(cd "$bundle" && pwd)"
abs_artifact="$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")"
"$harness" "$abs_bundle" "$out_dir/tuple.json" \
  --artifact-sha256 "$artifact_sha256" --artifact-size "$artifact_size" \
  --artifact-url "$artifact_url" --runtime-version "$version" --channel "$channel"

# ── 5. draft for the issuer ──────────────────────────────────────────────────
now=$(date +%s)
expires=$((now + 14 * 24 * 3600))
draft="$out_dir/draft.json"
DRAFT_JSON="$draft" TUPLE_JSON="$out_dir/tuple.json" VERSION="$version" \
PROFILE_ID="$profile_id" CHANNEL="$channel" MIN_OS="macos-13" NOW="$now" \
EXPIRES="$expires" ARTIFACT_PATH="$abs_artifact" ARTIFACT_URL="$artifact_url" \
python3 <<'PYEOF'
import json, os
tuple_doc = json.load(open(os.environ["TUPLE_JSON"]))
target, tuple_v3 = tuple_doc["target"], tuple_doc["tuple"]
digests = tuple_v3["digests"]
assert target["profileId"] == os.environ["PROFILE_ID"], "harness profile id mismatch"
assert target["version"] == os.environ["VERSION"], "harness version mismatch"
assert target["channel"] == os.environ["CHANNEL"], "harness channel mismatch"
assert target["bundleSha256"] == digests["contractSha256"], "contract digest mismatch"
assert target["runtimeDigest"] == digests["daemonSha256"], "runtime digest mismatch"
draft = {
    "schemaVersion": 1,
    "artifactPath": os.environ["ARTIFACT_PATH"],
    "artifactUrl": os.environ["ARTIFACT_URL"],
    "productId": target["productId"],
    "version": target["version"],
    "currentVersion": target["version"],
    "platform": target["platform"],
    "arch": target["arch"],
    "releaseCandidateSha256": target["releaseCandidateSha256"],
    "minOs": os.environ["MIN_OS"],
    "profileId": target["profileId"],
    "bundleSha256": target["bundleSha256"],
    "runtimeVersion": target["runtimeVersion"],
    "runtimeDigest": target["runtimeDigest"],
    "channel": target["channel"],
    "publishedAtUnixSeconds": int(os.environ["NOW"]),
    "expiresAtUnixSeconds": int(os.environ["EXPIRES"]),
    "rollbackFloor": "0.0.1",
    "rootVersion": 1,
    "targetsVersion": 1,
    "snapshotVersion": 1,
    "timestampVersion": 1,
    "nativeEnrollmentTuplePath": os.environ["TUPLE_JSON"],
}
json.dump(draft, open(os.environ["DRAFT_JSON"], "w"))
PYEOF

# ── 6. unlock the dev keychain and issue the signed metadata ────────────────
security unlock-keychain -p "$(cat "$metadata_dir/keychain-pass")" "$keychain"
issued="$out_dir/issued-metadata.json"
"$producer" issue --draft "$draft" --output "$issued" --keychain-ref "$keychain"

ISSUED_JSON="$issued" VERSION="$version" PROFILE_ID="$profile_id" CHANNEL="$channel" \
TUPLE_JSON="$out_dir/tuple.json" python3 <<'PYEOF'
import json, os
issued = json.load(open(os.environ["ISSUED_JSON"]))
tuple_doc = json.load(open(os.environ["TUPLE_JSON"]))
target = issued["targets"]["target"]
digests = tuple_doc["tuple"]["digests"]
assert issued["schemaVersion"] == 2, "issued metadata schema"
assert len(issued["rootSignatures"]) == 2 and len(issued["targetsSignatures"]) == 2
assert target["version"] == os.environ["VERSION"], "issued version mismatch"
assert target["profileId"] == os.environ["PROFILE_ID"], "issued profile id mismatch"
assert target["channel"] == os.environ["CHANNEL"], "issued channel mismatch"
assert target["bundleSha256"] == digests["contractSha256"], "issued bundle digest mismatch"
assert target["runtimeDigest"] == digests["daemonSha256"], "issued runtime digest mismatch"
embedded = target.get("nativeEnrollmentTupleV3")
assert embedded is not None, "issued metadata does not embed native_enrollment_tuple_v3"
assert embedded == tuple_doc["tuple"], "embedded tuple differs from the produced tuple"
assert len(embedded["digests"]) == 10, "embedded tuple must carry 10 digests"
PYEOF

# ── 7. seed the installed-update journals for native admission ──────────────
updates_dir="$HOME/Library/Application Support/com.runne.desktop/bundled-runtime/updates"
mkdir -p "$updates_dir"
rm -f "$updates_dir/install-state.json"* "$updates_dir/trust-state.json"* "$updates_dir/installed-metadata.json"*
UPDATES_DIR="$updates_dir" ISSUED_JSON="$issued" VERSION="$version" \
ARTIFACT_SHA256="$artifact_sha256" STAGED_PATH="$abs_artifact" python3 <<'PYEOF'
import hashlib, json, os
updates = os.environ["UPDATES_DIR"]
issued_bytes = open(os.environ["ISSUED_JSON"], "rb").read()
assert issued_bytes.endswith(b"\n")
# InstalledUpdateMetadataJournal::persist stores serde_json::to_vec bytes (no newline).
metadata_bytes = issued_bytes.rstrip(b"\n")
metadata_sha256 = hashlib.sha256(metadata_bytes).hexdigest()
with open(os.path.join(updates, "installed-metadata.json.1.json"), "wb") as handle:
    handle.write(metadata_bytes)
install_record = {
    "schemaVersion": 2,
    "state": "committed",
    "version": os.environ["VERSION"],
    "artifactSha256": os.environ["ARTIFACT_SHA256"],
    "metadataSha256": metadata_sha256,
    "stagedPath": os.environ["STAGED_PATH"],
}
with open(os.path.join(updates, "install-state.json.1.json"), "w") as handle:
    json.dump(install_record, handle)
trust_state = {
    "schemaVersion": 1,
    "rootVersion": 1,
    "snapshotVersion": 1,
    "installedVersion": os.environ["VERSION"],
    "rollbackFloor": "0.0.1",
}
with open(os.path.join(updates, "trust-state.json.1.json"), "w") as handle:
    json.dump(trust_state, handle)
PYEOF

cat <<SUMMARY
Dev update metadata issued:
  tuple:            $out_dir/tuple.json
  draft:            $draft
  issued metadata:  $issued
  artifact:         $abs_artifact (sha256 $artifact_sha256)
  updates dir:      $updates_dir
    install-state.json.1.json  trust-state.json.1.json  installed-metadata.json.1.json
  release binding:  profileId=$profile_id version=$version channel=$channel
Note: the issued metadata embeds the produced NativeEnrollmentTupleV3 from
$out_dir/tuple.json (draft nativeEnrollmentTuplePath); the issuer re-validated
it against the draft, and the runtime admission path additionally re-measures
the installed bundle against the embedded tuple at install time.
SUMMARY
