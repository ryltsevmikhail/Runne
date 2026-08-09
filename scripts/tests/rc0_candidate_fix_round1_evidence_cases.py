import importlib
import fcntl
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


def bind_artifact_path(records, path):
    records["artifact-inventory.json"]["artifacts"][0]["relative_path"] = path
    records["checksums.txt"] = records["checksums.txt"].replace(
        b"dist/gocode.tar", path.encode("ascii")
    )
    records["sbom.spdx.json"]["artifact_bindings"][0]["relative_path"] = path


class Rc0CandidateEvidenceFixRound1Tests(unittest.TestCase):
    def test_url_values_reject_credentials_queries_fragments_and_encoding(self):
        evidence = evidence_module()
        values = (
            "https://user:password@example.invalid/spdx",
            "https://example.invalid/spdx?access_token=x",
            "https://example.invalid/spdx?api_key=x",
            "https://example.invalid/spdx?signature=x",
            "https://example.invalid/spdx?password=x",
            "https://example.invalid/spdx#credential",
            "https://user%3Apassword%40example.invalid/spdx",
            "https://example.invalid/spdx/%2f%2e%2e%2fsecret",
        )
        for value in values:
            records = fixture_records()
            records["sbom.spdx.json"]["documentNamespace"] = value
            with self.subTest(value=value), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(records, Path(output), Path(checkout))

        records = fixture_records()
        records["sbom.spdx.json"]["packages"] = [{
            "SPDXID": "SPDXRef-download", "name": "fixture", "versionInfo": "1",
            "downloadLocation": "https://example.invalid/a?token=x",
            "licenseConcluded": "NOASSERTION",
        }]
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(records, Path(output), Path(checkout))

    def test_artifact_graph_excludes_logs_reports_and_authority_outputs(self):
        evidence = evidence_module()
        paths = (
            "logs/candidate.log", "dist/logs/candidate.txt", "reports/result.json",
            "dist/reports/result.json", "verification-report.json",
            "dist/qualification-declaration.json", "dist/gate-verdict.json",
            "dist/source-candidate-gate.json", "dist/declaration/result.json",
            "dist/verdict/result.json", "dist/gate/output.json",
            "docs/evidence/rc0-candidates/" + "9" * 40 + "/verification-report.json",
        )
        for path in paths:
            records = fixture_records()
            bind_artifact_path(records, path)
            with self.subTest(path=path), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(records, Path(output), Path(checkout))

    def test_three_contenders_never_delete_a_foreign_lock(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            lock = root / f".{SOURCE}.construction-lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(descriptor, b"foreign-active-lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = lock.stat(); barrier = threading.Barrier(3)

            def contend():
                barrier.wait()
                try:
                    evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
                except evidence.EvidenceConstructionError:
                    return "blocked"
                return "built"

            with ThreadPoolExecutor(max_workers=3) as pool:
                results = tuple(pool.map(lambda _index: contend(), range(3)))
            after = lock.stat()
            self.assertEqual(results, ("blocked", "blocked", "blocked"))
            self.assertEqual(lock.read_bytes(), b"foreign-active-lock")
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertFalse((root / SOURCE).exists())
            os.close(descriptor)

    def test_atomic_publication_never_replaces_file_directory_or_symlink_racer(self):
        evidence = evidence_module()
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                marker = b"racer"
                final = Path(output) / SOURCE
                if kind == "file":
                    final.write_bytes(marker)
                elif kind == "directory":
                    final.mkdir()
                else:
                    final.symlink_to("foreign-target")

                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(fixture_records(), Path(output), Path(checkout))
                if kind == "file":
                    self.assertEqual(final.read_bytes(), marker)
                elif kind == "directory":
                    self.assertEqual(tuple(final.iterdir()), ())
                else:
                    self.assertTrue(final.is_symlink())
                    self.assertEqual(os.readlink(final), "foreign-target")

    def test_atomic_publication_fails_closed_when_noreplace_is_unavailable(self):
        atomic = importlib.import_module("scripts.rc0_candidate.atomic_publish")
        evidence = evidence_module()
        with patch.object(atomic, "_LINKAT", None, create=True), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(fixture_records(), Path(output), Path(checkout))

    def test_output_root_rejects_dotdot_alias(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            alias = root / ".." / root.name
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(fixture_records(), alias, Path(checkout))

    def test_final_directory_substitution_cannot_publish_completion(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            def replace_final(root_fd, name):
                os.rename(name, name + ".owned", src_dir_fd=root_fd, dst_dir_fd=root_fd)
                os.mkdir(name, 0o700, dir_fd=root_fd)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), Path(output), Path(checkout), publication_hook=replace_final
                )
            self.assertTrue((Path(output) / SOURCE).is_dir())
            self.assertFalse((Path(output) / (SOURCE + ".owned")).exists())
            self.assertFalse((Path(output) / ("." + SOURCE + ".complete")).exists())

    def test_replaced_owned_lock_is_preserved_and_blocks_publication(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:

            def replace_lock(root_fd, final_name):
                name = f".{final_name}.construction-lock"
                os.unlink(name, dir_fd=root_fd)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
                os.write(fd, b"foreign-replacement")
                os.close(fd)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), Path(output), Path(checkout), publication_hook=replace_lock
                )
            lock = Path(output) / f".{SOURCE}.construction-lock"
            self.assertEqual(lock.read_bytes(), b"foreign-replacement")
            self.assertFalse((Path(output) / SOURCE).exists())


if __name__ == "__main__":
    unittest.main()
