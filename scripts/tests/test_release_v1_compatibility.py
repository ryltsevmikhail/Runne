"""V1 daemon-only compatibility regression: V1 cannot masquerade as V2.

The V1 pipeline assembles a single-platform daemon-only candidate
(``release-manifest.v1.json``, ``qualification_state: assembled``) that its own
verifier can only block. The V2 structural verifier consumes a closed set of V2
fixture files and builds a product tuple; submitting any V1 daemon-only
structure must be refused as ``ManifestInvalid`` with no claims and no V2
product tuple, so V1 remains daemon-only and cannot masquerade as V2.
"""

import json
import subprocess
import unittest
from pathlib import Path

from scripts.tests.release_fixture_support import VerifyReleaseMixin
from scripts.tests.release_test_support import ReleaseTestCase

ROOT = Path(__file__).resolve().parents[2]
VERIFY_V2 = ROOT / "scripts/verify-release-v2.sh"

# V2 product-tuple artifacts; their absence proves no V2 qualification subject
# or claim matrix was produced from a V1 candidate.
V2_PRODUCT_TUPLE_FILES = (
    "manifest.v2.json",
    "product-tuple.v1.json",
    "qualification-subject.v1.json",
    "claim-matrix.v1.json",
)


class ReleaseV1CompatibilityTests(ReleaseTestCase, VerifyReleaseMixin):
    def test_v1_package_stays_assembled_daemon_only_without_v2_tuple(self) -> None:
        candidate = self.package_candidate()

        manifest = json.loads((candidate / "release-manifest.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["format"], "release-manifest.v1")
        self.assertEqual(manifest["qualification_state"], "assembled")
        self.assertEqual(manifest["candidate"]["release_version"], "1.2.3")
        for lane in manifest["candidate"]["qualification_lanes"]:
            for slot in lane["hosted_execution_slots"]:
                self.assertEqual(slot["status"], "planned")
                self.assertNotIn("hosted_runner", slot)
        for record in manifest["evidence"]:
            self.assertNotIn("hosted_runner", record)
        self._assert_no_v2_product_tuple(candidate)

    def test_v1_verifier_keeps_assembled_candidate_blocked_and_unchanged(self) -> None:
        candidate = self.package_candidate()
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertNotIn("manifest", report["blocked_gate_ids"])
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_v2_verifier_refuses_v1_candidate_without_claims_or_tuple(self) -> None:
        candidate = self.package_candidate()
        for fixture_flag in ((), ("--fixture",)):
            with self.subTest(fixture_flag=fixture_flag):
                candidate_before = self.snapshot_tree(candidate)

                result = self._run_verify_v2(candidate, fixture_flag)

                self.assertEqual(result.returncode, 1)
                document = json.loads(result.stdout)
                self.assertEqual(document["schema_version"], "release-v2-cli-result.v1")
                # The closed V2 artifact model refuses the V1 tree either at the
                # strict mode gate (ArtifactModeMismatch: V1 `mkdir -p` creates
                # 0775 directories under umask 0002 while V2 requires exactly
                # 0755) or at the closed file-set gate (ManifestInvalid under a
                # 022 umask). Both are typed refusals with no claims/tuple.
                self.assertIn(
                    document["error"]["code"],
                    ("ManifestInvalid", "ArtifactModeMismatch"),
                )
                self.assertIn("verification failed", result.stderr)
                # A V1 candidate must never reach the claims-bearing gate report
                # (overall_status BLOCKED_EVIDENCE is reserved for validated V2
                # structural fixtures); it is refused before any tuple exists.
                self.assertNotIn("overall_status", document)
                self.assertNotIn("claims", document)
                self.assertNotIn("qualification_subject_sha256", document)
                self.assertNotIn("candidate_sha256", document)
                self.assertEqual(candidate_before, self.snapshot_tree(candidate))
                self._assert_no_v2_product_tuple(candidate)

    def test_v1_manifest_cannot_masquerade_as_v2_manifest(self) -> None:
        candidate = self.package_candidate()
        masquerade = self.root / "masquerade"
        masquerade.mkdir()
        for path in candidate.rglob("*"):
            if path.is_file():
                relative = path.relative_to(candidate)
                (masquerade / relative).parent.mkdir(parents=True, exist_ok=True)
                (masquerade / relative).write_bytes(path.read_bytes())
        # Present the V1 manifest under the V2 manifest name; the closed V2 file
        # set must still reject the relabelled daemon-only structure. Normalize
        # modes to V2's exact set (0755 directories, 0644/0755 files) so the
        # refusal is deterministic (ManifestInvalid) regardless of the process
        # umask, which otherwise surfaces ArtifactModeMismatch first.
        (masquerade / "manifest.v2.json").write_bytes(
            (candidate / "release-manifest.v1.json").read_bytes()
        )
        (masquerade / "release-manifest.v1.json").unlink()
        for path in masquerade.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        masquerade_before = self.snapshot_tree(masquerade)

        result = self._run_verify_v2(masquerade, ())

        self.assertEqual(result.returncode, 1)
        document = json.loads(result.stdout)
        self.assertEqual(document["error"]["code"], "ManifestInvalid")
        self.assertNotIn("claims", document)
        self.assertNotIn("qualification_subject_sha256", document)
        self.assertEqual(masquerade_before, self.snapshot_tree(masquerade))
        # manifest.v2.json exists here only as the deliberately relabelled V1
        # manifest; no other V2 product-tuple artifact may have been created.
        self._assert_no_v2_product_tuple(
            masquerade, ignore=frozenset(("manifest.v2.json",))
        )

    def _run_verify_v2(
        self, candidate: Path, fixture_flag: tuple[str, ...]
    ) -> subprocess.CompletedProcess[str]:
        arguments = [str(VERIFY_V2), "--candidate", str(candidate)]
        arguments.extend(fixture_flag)
        return subprocess.run(
            arguments,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _assert_no_v2_product_tuple(
        self, candidate: Path, ignore: frozenset[str] = frozenset()
    ) -> None:
        for name in V2_PRODUCT_TUPLE_FILES:
            if name in ignore:
                continue
            self.assertFalse(
                (candidate / name).exists(),
                f"V2 product tuple artifact created: {name}",
            )


if __name__ == "__main__":
    unittest.main()
