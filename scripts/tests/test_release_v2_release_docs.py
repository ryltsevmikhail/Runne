"""Contracts for inert Task 12 human-artifact fixtures, not Task 15 documents."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.fixtures import generate_fixture
from scripts.release_v2.human_fixture_commands import contains_production_command
from scripts.release_v2 import human_fixture_validation as human_validation
from scripts.release_v2.human_fixture_validation import (
    snapshot_human_fixture,
    validate_human_fixture,
)
from scripts.release_v2.inventory import TreeBytes
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


_HUMAN_FILES = ("changelog.md", "release-notes.md", "rollback.md", "pr-description.md", "merge-checklist.md")
class ReleaseDocumentsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "fixture"
        generate_fixture(self.root)
        self.human = self.root / "human"
        self.binding = json.loads((self.human / "binding.v1.json").read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _document(self, name: str) -> str:
        return (self.human / name).read_text(encoding="utf-8")

    def _replace(self, name: str, old: str, new: str) -> None:
        path = self.human / name
        path.write_text(self._document(name).replace(old, new), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.human / f"{name}.sha256").write_text(f"{digest}  human/{name}\n", encoding="utf-8")

    def _blocks(self, code: FailureCodeV1) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            validate_human_fixture(self.root)
        self.assertIs(raised.exception.code, code)

    def test_at_43_bound_changelog_and_notes_are_accepted(self) -> None:
        result = validate_human_fixture(self.root)
        self.assertEqual(result.fixture_class, "STRUCTURAL_FIXTURE_ONLY")
        self.assertFalse(result.production_approved)

    def test_at_43_unbound_changelog_or_notes_blocks(self) -> None:
        self._replace("release-notes.md", self.binding["candidate_sha256"], "0" * 64)
        self._blocks(FailureCodeV1.CANDIDATE_IDENTITY_MISMATCH)

    def test_at_44_rollback_preflight_is_not_run(self) -> None:
        self.assertEqual(validate_human_fixture(self.root).fixture_class, "STRUCTURAL_FIXTURE_ONLY")

    def test_at_44_rollback_claim_or_invalid_binding_blocks(self) -> None:
        self._replace("rollback.md", "ROLLBACK_COMPATIBILITY_PREFLIGHT: NOT_RUN", "ROLLBACK_COMPATIBILITY_PREFLIGHT: COMPATIBLE")
        self._blocks(FailureCodeV1.ROLLBACK_UNSUPPORTED)

    def test_at_45_clean_pr_merge_checklists_are_accepted(self) -> None:
        self.assertEqual(validate_human_fixture(self.root).fixture_class, "STRUCTURAL_FIXTURE_ONLY")

    def test_at_45_pr_merge_gate_blocks_violation(self) -> None:
        self._replace("merge-checklist.md", "MERGE_REQUIRED_GATE: source-candidate-binding=REQUIRED_NOT_RUN", "MERGE_REQUIRED_GATE: source-candidate-binding=PASSED")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_at_46_structural_package_has_no_production_command(self) -> None:
        self.assertFalse(validate_human_fixture(self.root).production_approved)

    def test_at_46_production_action_command_blocks(self) -> None:
        self._replace("changelog.md", "# Fixture changelog", "# Fixture changelog\n\ncurl https://example.invalid")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_npm_publish_command_marker_blocks(self) -> None:
        self._replace("changelog.md", "# Fixture changelog", "# Fixture changelog\n\nnpm publish")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_extra_prose_upload_marker_blocks(self) -> None:
        self._replace("changelog.md", "# Fixture changelog", "# Fixture changelog\n\nupload artifact")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_extra_prose_deploy_marker_blocks(self) -> None:
        self._replace("changelog.md", "# Fixture changelog", "# Fixture changelog\n\ndeploy production")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_extra_prose_publish_marker_blocks(self) -> None:
        self._replace("changelog.md", "# Fixture changelog", "# Fixture changelog\n\npublish the fixture report")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_git_global_option_tag_or_push_blocks(self) -> None:
        for command in ("git --no-pager tag v0.0.0", "git -C . push origin main"):
            with self.subTest(command=command):
                self._replace("changelog.md", "# Fixture changelog", f"# Fixture changelog\n\n{command}")
                self._blocks(FailureCodeV1.MANIFEST_INVALID)
                self._replace("changelog.md", f"# Fixture changelog\n\n{command}", "# Fixture changelog")

    def test_package_release_and_infrastructure_commands_block(self) -> None:
        commands = ("npm publish", "pnpm publish", "cargo publish", "gh release create v0.0.0", "kubectl apply -f fixture.yaml")
        for command in commands:
            with self.subTest(command=command):
                self._replace("changelog.md", "# Fixture changelog", f"# Fixture changelog\n\n{command}")
                self._blocks(FailureCodeV1.MANIFEST_INVALID)
                self._replace("changelog.md", f"# Fixture changelog\n\n{command}", "# Fixture changelog")

    def test_static_command_scanner_blocks_wrappers_paths_and_separators(self) -> None:
        commands = (
            "/usr/bin/npm publish", "./npm publish", "env RELEASE=1 npm publish", "env -- RELEASE=1 npm publish",
            "RELEASE=1 npm publish", "BUILD=1 RELEASE=1 /usr/bin/npm publish", "RELEASE-=1 npm publish",
            "command npm publish", "nohup npm publish", "time -p npm publish",
            "sudo npm publish", "doas npm publish", "printf inert; npm publish",
            "printf inert; RELEASE=1 npm publish",
            "printf inert && pnpm publish", "printf inert | cargo publish",
            'sh -c "npm publish"', 'bash -c "git -C . push origin main"',
            "npm $(printf publish)", "$(printf npm) publish", "`printf npm` publish", "printf inert; npm $(printf publish)",
            "gh --repo org/repo release create v0.0.0", "yarn publish",
            "wget https://example.invalid", "git --no-pager tag v0.0.0",
            "env --bad", "command --bad", "sh -c", "git --unknown-option",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(contains_production_command(command))

    def test_static_command_scanner_accepts_normal_prose(self) -> None:
        prose = (
            "Please publish the fixture report after review.",
            "Do not upload or deploy this structural fixture.",
            "The release checklist records an inert command example.",
            "This prose describes $(command substitution) and `backticks` as inert syntax.",
        )
        for text in prose:
            with self.subTest(text=text):
                self.assertFalse(contains_production_command(text))

    def test_static_command_scanner_accepts_assignment_only_segment(self) -> None:
        self.assertFalse(contains_production_command("RELEASE=1 BUILD=fixture"))

    def test_at_47_relative_redacted_markers_are_accepted(self) -> None:
        self.assertEqual(validate_human_fixture(self.root).fixture_class, "STRUCTURAL_FIXTURE_ONLY")

    def test_at_47_secret_or_absolute_marker_blocks(self) -> None:
        self._replace("release-notes.md", "PATHS: RELATIVE_ONLY", "PATHS: /home/fixture\ntoken=value")
        self._blocks(FailureCodeV1.PATH_UNSAFE)

    def test_at_48_fixture_verification_preserves_bytes(self) -> None:
        before = snapshot_human_fixture(self.root)
        self.assertIsInstance(before, TreeBytes)
        validate_human_fixture(self.root, before=before)
        self.assertEqual(before, snapshot_human_fixture(self.root))

    def test_validator_uses_captured_bytes_without_path_reopens(self) -> None:
        before = snapshot_human_fixture(self.root)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("path reopened")):
            self.assertEqual(validate_human_fixture(self.root, before=before).fixture_class, "STRUCTURAL_FIXTURE_ONLY")

    def test_at_48_post_verification_byte_change_blocks(self) -> None:
        before = snapshot_human_fixture(self.root)
        self._replace("release-notes.md", "# Fixture release notes", "# Changed fixture release notes")
        self._blocks_with_before(before, FailureCodeV1.INPUT_MUTATION_DETECTED)

    def test_final_tree_recapture_detects_added_directory(self) -> None:
        before = snapshot_human_fixture(self.root)
        original, calls = human_validation.snapshot_human_fixture, 0

        def capture(root: Path) -> TreeBytes:
            nonlocal calls
            value = original(root)
            calls += 1
            if calls == 1:
                directory = self.root / "injected"
                directory.mkdir()
                os.chmod(directory, 0o755)
            return value

        with patch.object(human_validation, "snapshot_human_fixture", side_effect=capture):
            self._blocks_with_before(before, FailureCodeV1.INPUT_MUTATION_DETECTED)

    def test_content_byte_tampering_blocks_before_document_checks(self) -> None:
        archive = self.root / "archive.tar"
        archive.write_bytes(archive.read_bytes() + b"tampered")
        self._blocks(FailureCodeV1.ARTIFACT_DIGEST_MISMATCH)

    def test_noncanonical_sidecar_digest_blocks(self) -> None:
        sidecar = self.human / "changelog.md.sha256"
        sidecar.write_text(f"{'A' * 64}  human/changelog.md\n", encoding="utf-8")
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_checksums_manifest_has_a_verified_sidecar(self) -> None:
        sidecar = self.root / "checksums.sha256.sha256"
        self.assertTrue(sidecar.is_file())
        self.assertEqual(sidecar.read_text(encoding="utf-8"), f"{hashlib.sha256((self.root / 'checksums.sha256').read_bytes()).hexdigest()}  checksums.sha256\n")

    def test_checksum_manifest_is_parsed_against_artifact_inventory(self) -> None:
        checksums = self.root / "checksums.sha256"
        checksums.write_bytes(b"not canonical\n")
        (self.root / "checksums.sha256.sha256").write_text(f"{hashlib.sha256(checksums.read_bytes()).hexdigest()}  checksums.sha256\n", encoding="utf-8")
        self._blocks(FailureCodeV1.CHECKSUM_INVALID)

    def test_exact_tree_rejects_extra_directory(self) -> None:
        unexpected = self.root / "unexpected"
        unexpected.mkdir()
        os.chmod(unexpected, 0o755)
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def _blocks_with_before(self, before: dict[str, str], code: FailureCodeV1) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            validate_human_fixture(self.root, before=before)
        self.assertIs(raised.exception.code, code)
