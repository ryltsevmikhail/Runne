import hashlib
import importlib
import json
import os
import stat
import struct
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SOURCE = "a" * 40
ATTEMPT = "018f0000-0000-7000-8000-000000000000"
POLICY = "b" * 64
PINNED = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"


def evidence_module():
    try:
        return importlib.import_module("scripts.rc0_candidate.evidence")
    except ModuleNotFoundError as error:
        raise AssertionError("candidate evidence builder is absent") from error


def fixture_records():
    identity = {
        "repository_id": "gocode",
        "candidate_source_revision": SOURCE,
        "evidence_attempt_id": ATTEMPT,
        "policy_digest": POLICY,
        "profile": "gocode.rc0.evidence-profile/3",
    }
    artifact = {
        "relative_path": "dist/gocode.tar",
        "sha256": "c" * 64,
        "size": 3,
        "locator": "cas:sha256:" + "c" * 64,
        "kind": "UNSIGNED_ARCHIVE",
    }
    records = {
        "candidate-record.json": {"schema_id": "gocode.rc0.schema.candidate-record/3", **identity},
        "source-gate-results.json": {
            "schema_id": "gocode.rc0.schema.source-gate-results/3", **identity,
            "capture": {
                "remote_url": "https://github.com/Ryltsevmg/gocode",
                "captured_origin_main_revision": SOURCE, "head_revision": SOURCE,
                "raw_tree_oid": "d" * 40, "current_tree_oid": "d" * 40,
                "raw_gitmodules_sha256": "e" * 64,
                "current_gitmodules_sha256": "e" * 64,
                "raw_opencode_gitlink_revision": PINNED,
                "current_opencode_gitlink_revision": PINNED,
                "capture_evidence_kind": "RAW_GIT_OBJECTS", "tree_clean": True,
            },
        },
        "test-inventory.json": {
            "schema_id": "gocode.rc0.schema.test-inventory/3", **identity,
            "inventory_status": "FROZEN", "final_inventory_digest": "f" * 64, "tests": [],
        },
        "security-validation.json": {
            "schema_id": "gocode.rc0.schema.security-validation/3", **identity,
            "validations": [{"validation_id": "fixture-scanner", "category": "SCANNER", "stage": "SOURCE_CANDIDATE", "execution_outcome": "PASS", "evidence_digest": "1" * 64}],
        },
        "documentation-validation.json": {
            "schema_id": "gocode.rc0.schema.documentation-validation/3", **identity,
            "validations": [{"validation_id": "fixture-docs", "category": "TAXONOMY", "execution_outcome": "PASS", "manifest_digest": "2" * 64}],
        },
        "fail-closed-disposition.json": {
            "schema_id": "gocode.rc0.schema.fail-closed-disposition/3", **identity,
            "dispositions": [{"subsystem": "SANDBOX", "stage": "SOURCE_CANDIDATE", "disposition": "NATIVE_SANDBOX_NOT_QUALIFIED"}],
        },
        "artifact-inventory.json": {
            "schema_id": "gocode.rc0.schema.artifact-inventory/3", **identity, "artifacts": [artifact],
        },
        "sbom.spdx.json": {
            "schema_id": "gocode.rc0.schema.sbom-spdx-2.3/3", **identity,
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT", "name": "fixture",
            "documentNamespace": "https://example.invalid/spdx/fixture",
            "artifact_bindings": [{key: artifact[key] for key in ("relative_path", "sha256")}],
            "packages": [],
        },
    }
    records["checksums.txt"] = (
        "repository_id=gocode\n" f"candidate_source_revision={SOURCE}\n"
        f"evidence_attempt_id={ATTEMPT}\n" f"policy_digest={POLICY}\n"
        + "c" * 64 + " 3 dist/gocode.tar\n"
    ).encode()
    return records


def fixture_records_v4():
    records = fixture_records()
    for value in records.values():
        if isinstance(value, dict):
            value["schema_id"] = value["schema_id"].removesuffix("/3") + "/4"
            value["profile"] = "gocode.rc0.evidence-profile/4"
    records["source-gate-results.json"]["capture"] = {
        "remote_url": "https://git.sourcecraft.dev/ryltsevmg/gocode.git",
        "captured_origin_main_revision": SOURCE,
        "head_revision": SOURCE,
        "raw_tree_oid": "d" * 40,
        "current_tree_oid": "d" * 40,
        "upstream_tree_oid": "e" * 40,
        "upstream_blob_count": 1,
        "upstream_content_digest": "f" * 64,
        "opencode_source_sha": PINNED,
        "capture_evidence_kind": "RAW_GIT_OBJECTS",
        "tree_clean": True,
    }
    return records


class Rc0CandidateEvidenceTests(unittest.TestCase):
    def test_evidence_commit_has_one_source_parent_and_only_nine_additions(self):
        evidence = evidence_module()
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(dir=root.parent) as location:
            repo = Path(location)
            command = lambda *args: subprocess.run(
                ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
            ).stdout.strip()
            command("init", "-q")
            command("config", "user.name", "RC0 Fixture")
            command("config", "user.email", "rc0-fixture@example.invalid")
            (repo / "README").write_text("source\n", encoding="utf-8")
            command("add", "README")
            command("commit", "-qm", "source")
            source = command("rev-parse", "HEAD")
            target = repo / "docs/evidence/rc0-candidates" / source
            target.mkdir(parents=True)
            for name in evidence.EVIDENCE_FILES:
                (target / name).write_bytes(name.encode())
            command("add", "docs/evidence")
            command("commit", "-qm", "evidence")
            revision = command("rev-parse", "HEAD")
            self.assertEqual(evidence.validate_fixture_evidence_commit(repo, source, revision), ())
            self.assertTrue(evidence.validate_fixture_evidence_commit(repo, "1" * 40, revision))

    def test_rejects_extra_symlink_mode_or_source_diff(self):
        evidence = evidence_module()
        entries = {name: {"mode": "100644", "type": "blob", "data": b"{}"} for name in evidence.EVIDENCE_FILES}
        self.assertEqual(evidence.validate_fixture_evidence_entries(SOURCE, entries), ())
        mutations = []
        extra = deepcopy(entries); extra["extra.json"] = {"mode": "100644", "type": "blob", "data": b"{}"}; mutations.append(extra)
        symlink = deepcopy(entries); symlink["candidate-record.json"]["type"] = "symlink"; mutations.append(symlink)
        mode = deepcopy(entries); mode["candidate-record.json"]["mode"] = "100755"; mutations.append(mode)
        source_diff = deepcopy(entries); source_diff["../README"] = {"mode": "100644", "type": "blob", "data": b"changed"}; mutations.append(source_diff)
        for changed in mutations:
            with self.subTest(paths=tuple(changed)):
                self.assertTrue(evidence.validate_fixture_evidence_entries(SOURCE, changed))

    def test_evidence_digest_has_exact_path_and_blob_framing(self):
        evidence = evidence_module()
        blobs = {name: name.encode("ascii") for name in evidence.EVIDENCE_FILES}
        actual = evidence.evidence_bundle_digest(SOURCE, blobs)
        expected = hashlib.sha256()
        expected.update(b"GOCODE_RC0_EVIDENCE_V1\0")
        prefix = f"docs/evidence/rc0-candidates/{SOURCE}/"
        for name in sorted(blobs, key=lambda value: (prefix + value).encode("ascii")):
            path = (prefix + name).encode("ascii")
            data = blobs[name]
            expected.update(struct.pack(">I", len(path)))
            expected.update(path)
            expected.update(struct.pack(">Q", len(data)))
            expected.update(hashlib.sha256(data).digest())
        self.assertEqual(actual, expected.hexdigest())

    def test_checksum_spdx_artifact_bijection_is_exact(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            result = evidence.build_fixture_evidence(fixture_records(), Path(output), Path(checkout))
            self.assertEqual(set(result.blobs), set(evidence.EVIDENCE_FILES))

        for mutation in (
            "checksum", "spdx", "self-reference", "foreign-evidence-reference",
            "credential", "non-ascii-checksum",
        ):
            records = fixture_records()
            if mutation == "checksum":
                records["checksums.txt"] = records["checksums.txt"].replace(b"dist/gocode.tar", b"dist/other.tar")
            elif mutation == "spdx":
                records["sbom.spdx.json"]["artifact_bindings"][0]["sha256"] = "9" * 64
            else:
                path = f"docs/evidence/rc0-candidates/{SOURCE}/candidate-record.json"
                if mutation == "credential":
                    records["sbom.spdx.json"]["packages"] = [{
                        "SPDXID": "SPDXRef-secret", "name": "fixture", "versionInfo": "1",
                        "downloadLocation": "https://user:secret@example.invalid/a",
                        "licenseConcluded": "NOASSERTION",
                    }]
                    path = "dist/gocode.tar"
                elif mutation == "non-ascii-checksum":
                    path = "dist/gocodé.tar"
                elif mutation == "foreign-evidence-reference":
                    path = "docs/evidence/rc0-candidates/" + "9" * 40 + "/candidate-record.json"
                records["artifact-inventory.json"]["artifacts"][0]["relative_path"] = path
                records["checksums.txt"] = records["checksums.txt"].replace(b"dist/gocode.tar", path.encode())
                records["sbom.spdx.json"]["artifact_bindings"][0]["relative_path"] = path
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(records, Path(output), Path(checkout))
                self.assertEqual(tuple(Path(output).iterdir()), ())

    def test_builder_is_owner_private_atomic_and_refuses_collision(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            result = evidence.build_fixture_evidence(fixture_records(), Path(output), Path(checkout))
            self.assertEqual(stat.S_IMODE(result.directory.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in result.directory.iterdir()))
            before = {path.name: path.read_bytes() for path in result.directory.iterdir()}
            retry = evidence.build_fixture_evidence(
                fixture_records(), Path(output), Path(checkout)
            )
            self.assertEqual(retry.directory, result.directory)
            self.assertEqual(before, {path.name: path.read_bytes() for path in result.directory.iterdir()})
            self.assertFalse((result.directory / "verification-report.json").exists())


from scripts.tests.rc0_candidate_fix_round1_evidence_cases import (
    Rc0CandidateEvidenceFixRound1Tests,
)
from scripts.tests.rc0_candidate_fix_round2_evidence_cases import (
    Rc0CandidateEvidenceFixRound2Tests,
)
from scripts.tests.rc0_candidate_fix_round3_evidence_cases import (
    Rc0CandidateEvidenceFixRound3Tests,
)
from scripts.tests.rc0_candidate_fix_round4_evidence_cases import (
    Rc0CandidateEvidenceFixRound4Tests,
)
from scripts.tests.rc0_candidate_fix_round5_evidence_cases import (
    Rc0CandidateEvidenceFixRound5Tests,
)
from scripts.tests.rc0_candidate_fix_round6_evidence_cases import (
    Rc0CandidateEvidenceFixRound6Tests,
)
from scripts.tests.rc0_candidate_v4_cases import Rc0CandidateEvidenceV4Tests


if __name__ == "__main__":
    unittest.main()
