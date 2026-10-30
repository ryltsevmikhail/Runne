#!/usr/bin/env bash
# macOS owner-dev signed-metadata workflow with a local qualification receipt.
#
# The result is operational local evidence on the owner's dev keys. It is not
# third-party attestation, not release qualification, and not a substitute for
# ops preprod provenance.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: dev-macos-signed-workflow.sh qualify

Runs the macOS analogue of the Linux qualification workflow on the assembled
signed dev bundle (target/dev-bundle/Runne.app, built by dev-signed-run.sh
--credential-service):

  1. refuse a dirty tree, a bundle whose release candidate is not HEAD, or an
     already used qualification run directory
  2. package the dev artifact and generate a fresh qualification receipt
     (scripts/desktop/dev-macos-qualification-receipt.sh)
  3. produce the NativeEnrollmentTupleV3 with the qualification row
  4. issue threshold-signed UpdateMetadataV2 with the dev keychain
  5. seed the installed-update journals and report the admission verdict

Exit codes: 0 qualified metadata issued, 1 any step failed (fail closed),
2 usage error.
USAGE
}

fail() { echo "error: $*" >&2; exit 1; }
[[ $# == 1 && "$1" == "qualify" ]] || { usage >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
[[ "$(uname -s):$(uname -m)" == "Darwin:arm64" ]] || fail "requires macOS arm64"

bundle="target/dev-bundle/Runne.app"
[[ -d "$bundle" ]] || fail "signed dev bundle not found: $bundle (run dev-signed-run.sh --credential-service --no-run)"
git diff --quiet HEAD -- || fail "source tree has tracked changes; commit before qualification"
[[ -z "$(git status --porcelain --untracked-files=all -- . ':(exclude).tmp-tools')" ]] \
  || fail "source tree has untracked files; commit or remove them before qualification"

source_commit="$(git rev-parse --verify HEAD^{commit})"
candidate_sha256="$(printf '%s' "$source_commit" | shasum -a 256 | awk '{print $1}')"
binding="$bundle/Contents/Resources/native-enrollment/release-candidate-binding.json"
[[ -f "$binding" ]] || fail "bundle has no staged release-candidate binding"
binding_candidate="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["releaseCandidateSha256"])' "$binding")"
[[ "$binding_candidate" == "$candidate_sha256" ]] \
  || fail "bundle release candidate is not $source_commit; rebuild the signed bundle"

run_dir="target/dev-macos-qualification/${source_commit:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
[[ ! -e "$run_dir" ]] || fail "qualification run directory already exists: $run_dir"
mkdir -p "$run_dir"

echo "Source commit:   $source_commit"
echo "Run directory:   $run_dir"
echo "Evidence scope:  local operational evidence on dev keys (not release qualification)"
RUNNE_FINALIZE_QUALIFICATION=1 RUNNE_MACOS_QUALIFICATION_DIR="$repo_root/$run_dir" \
  "$repo_root/scripts/desktop/dev-update-metadata.sh"

issued="target/dev-metadata/update/issued-metadata.json"
trust_manifest="target/dev-metadata/dev-trust-manifest.json"
receipt="$run_dir/receipt.json"
[[ -f "$issued" && -f "$receipt" ]] || fail "workflow did not produce the issued metadata and receipt"
echo "Verifying signed metadata and qualified tuple admission against the staged bundle..."
cargo build -q -p runne-platform-desktop --example dev_installed_admission --locked
"target/debug/examples/dev_installed_admission" \
  --metadata "$issued" --trust-manifest "$trust_manifest" --bundle "$bundle" \
  | tee "$run_dir/admission.txt"
ISSUED="$issued" RECEIPT="$receipt" SOURCE_COMMIT="$source_commit" RUN_DIR="$run_dir" \
python3 <<'PYVERDICT'
import hashlib, json, os, pathlib, time

issued = json.load(open(os.environ["ISSUED"], encoding="utf-8"))
target = issued["targets"]["target"]
tuple_v3 = target["nativeEnrollmentTupleV3"]
row = tuple_v3["nativeEnrollmentQualification"]
receipt_bytes = pathlib.Path(os.environ["RECEIPT"]).read_bytes()
receipt = json.loads(receipt_bytes)

assert row["receiptSha256"] == hashlib.sha256(receipt_bytes).hexdigest()
assert row["qualifiedAtUnixSeconds"] == receipt["qualifiedAtUnixSeconds"]
assert row["expiresAtUnixSeconds"] == receipt["expiresAtUnixSeconds"]
assert row["expiresAtUnixSeconds"] <= target["expiresAtUnixSeconds"]
source_commit = os.environ["SOURCE_COMMIT"]
candidate = hashlib.sha256(source_commit.encode("ascii")).hexdigest()
assert receipt["sourceCommit"] == source_commit
assert target["releaseCandidateSha256"] == candidate
assert tuple_v3["digests"]["candidateSha256"] == candidate
assert tuple_v3["digests"]["desktopSha256"] == receipt["desktopSha256"]
assert tuple_v3["digests"]["credentialServiceSha256"] == receipt["credentialServiceSha256"]
now = int(time.time())
admitted = row["qualifiedAtUnixSeconds"] <= now < row["expiresAtUnixSeconds"]
assert admitted, "qualification window is not open at verification time"
print(f"qualified_admission=some candidate_sha256={candidate}")
print(f"row={row['platform']}/{row['architecture']}/{row['packageKind']} "
      f"qualified_at={row['qualifiedAtUnixSeconds']} expires_at={row['expiresAtUnixSeconds']}")
print(f"metadata_expires_at={target['expiresAtUnixSeconds']} row_within_target=yes")
PYVERDICT

cat <<SUMMARY

macOS local qualification workflow completed.
  bundle:            $bundle
  receipt:           $receipt
  check log:         $run_dir/checks.log
  issued metadata:   $issued
  updates dir:       $HOME/Library/Application Support/com.runne.desktop/bundled-runtime/updates
Scope: the row is a digest-bound local operational record on dev signing keys.
It is not third-party attestation and it is not release qualification; run the
ops preprod qualification for cryptographic provenance.
SUMMARY
