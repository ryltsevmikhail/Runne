"""Closed-world tests for fixture-only platform claim migration."""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from unittest import mock

from scripts.rc0_policy.claim_migration import (
    ClaimMigrationFailure,
    _lineage,
    _rows,
    validate_claim_registry,
)
from scripts.rc0_policy.platform_policy_mapping import _lineage as mapping_lineage
from scripts.rc0_policy.canonical import loads_canonical
from scripts.tests.rc0_platform_claim_support import changed, closure_document, decision_log_document, overlap_vector, task3_claim_registry, temporary_index_fixture, valid_claim_registry, with_lineage
from scripts.tests.rc0_platform_claim_round5_cases import ClaimClosureRound5Cases
from scripts.tests.rc0_platform_policy_support import valid_mapping_fixture


class ClaimMigrationTests(ClaimClosureRound5Cases, unittest.TestCase):
    def validate(self, repo, registry=None, base=None, delta=None, composed=None):
        values = valid_claim_registry(repo)
        return validate_claim_registry(repo.root, registry or values[0], base or values[1], delta or values[2], composed or values[3])

    def test_rejects_missing_duplicate_extra_or_late_tracked_claim(self) -> None:
        with temporary_index_fixture() as repo:
            registry, base, delta, composed = valid_claim_registry(repo)
            for path in (
                "docs/adr/LATE_PLATFORM_CLAIM.md",
                "docs/desktop/adr/LATE_PLATFORM_CLAIM.md",
                "docs/release/LATE_PLATFORM_CLAIM.md",
                "notes/LATE_PLATFORM_CLAIM.markdown",
            ):
                repo.add_markdown(path, "Windows Server 2025 is the v1 production target.")
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_EXPECTED_PATH_SET_MISMATCH"):
                validate_claim_registry(repo.root, registry, base, delta, composed)

    def test_valid_fixture_returns_byte_exact_occurrences(self) -> None:
        with temporary_index_fixture() as repo:
            occurrences = self.validate(repo)
            self.assertEqual(
                [(item.claim_id, item.literal, item.path) for item in occurrences],
                [("NON_NORMATIVE_CONTEXT", "This is non-normative platform context.", "docs/notes/NON_NORMATIVE.md"),
                 ("V1_MACOS_PRODUCTION_DEVELOPER_ID", "macOS production Developer ID", "docs/notes/MACOS.md"),
                 ("V1_MANIFEST_V1_HANDOFF", "Manifest V1 handoff", "docs/notes/MANIFEST.md"),
                 ("V1_MOBILE_PLATFORM_FLOOR", "old mobile platform floor", "docs/notes/MOBILE.md"),
                 ("V1_NATIVE_THREE_PLATFORM_PRODUCTION", "native three-platform production", "docs/notes/NATIVE.md"),
                 ("V1_PHASE_10_PLATFORM_OWNERSHIP", "Phase 10 platform qualification ownership", "docs/notes/PHASE_10.md"),
                 ("V1_WINDOWS_SERVER_2025", "Windows Server 2025 is the v1 production target.", "docs/notes/PLATFORM_SCOPE.md")],
            )

    def test_registry_requires_exact_fields_and_sorted_unique_claims(self) -> None:
        with temporary_index_fixture() as repo:
            registry, *_ = valid_claim_registry(repo)
            variants = (
                lambda value: value.pop("registry_revision"),
                lambda value: value.__setitem__("unknown", True),
                lambda value: value.__setitem__("claims", list(reversed(value["claims"]))),
                lambda value: value["claims"][0].__setitem__("literal_needles", ["x", "x"]),
            )
            for mutate in variants:
                with self.subTest(mutate=mutate), self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_REGISTRY"):
                    self.validate(repo, registry=changed(registry, mutate))

    def test_base_delta_and_composed_universe_digests_and_path_sets_must_match(self) -> None:
        with temporary_index_fixture() as repo:
            registry, base, delta, composed = valid_claim_registry(repo)
            cases = (
                (changed(base, lambda value: value["rows"][0].__setitem__("content_sha256", "0" * 64)), delta, composed),
                (base, changed(delta, lambda value: value["rows"].reverse()), composed),
                (base, delta, changed(composed, lambda value: value["base_paths"].pop())),
            )
            for altered_base, altered_delta, altered_composed in cases:
                with self.subTest(), self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_LINEAGE_MISMATCH"):
                    self.validate(repo, base=altered_base, delta=altered_delta, composed=altered_composed)

    def test_actual_paths_equal_expected_paths_for_each_literal(self) -> None:
        with temporary_index_fixture() as repo:
            registry, *_ = valid_claim_registry(repo)
            variants = (
                changed(registry, lambda value: value["claims"][-1].__setitem__("expected_paths", ["docs/notes/MACOS.md"])),
                changed(registry, lambda value: value["claims"][-1].__setitem__("expected_paths", ["docs/history/PLATFORM_SCOPE.md", "docs/notes/PLATFORM_SCOPE.md"])),
            )
            for altered in variants:
                with self.subTest(altered=altered), self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_LINEAGE_MISMATCH"):
                    self.validate(repo, registry=altered)
            target = repo.root / "docs/notes/PLATFORM_SCOPE.md"
            repo.add_markdown("docs/notes/PLATFORM_SCOPE.md", "historical scope\n")
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_EXPECTED_PATH_SET_MISMATCH"):
                self.validate(repo)

    def test_rejects_unowned_or_unreasoned_non_normative_exclusion(self) -> None:
        with temporary_index_fixture() as repo:
            registry, *_ = valid_claim_registry(repo)
            for key, value in (("owner", ""), ("reason", "")):
                altered = changed(registry, lambda item, key=key, value=value: item["claims"][0].__setitem__(key, value))
                with self.subTest(key=key), self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_REGISTRY"):
                    self.validate(repo, registry=altered)

    def test_requires_both_adr_registries_logs_and_oq_closures(self) -> None:
        with temporary_index_fixture() as repo:
            paths = (("ADR-0027", "docs/adr/ADR-0027-v1-platform-scope.md", "Accepted"), ("ADR-0027", "docs/adr/README.md", "Accepted"), ("ADR-0027", "docs/decisions/DECISION_LOG.md", "Accepted"), ("ADR-0027", "docs/decisions/OPEN_QUESTIONS.md", "**Resolved**"), ("ADR-0015", "docs/desktop/adr/ADR-0015-v1-platform-scope.md", "Accepted"), ("ADR-0015", "docs/desktop/adr/README.md", "Accepted"), ("ADR-0015", "docs/desktop/decisions/DECISION_LOG.md", "Accepted"), ("ADR-0015", "docs/desktop/decisions/OPEN_QUESTIONS.md", "Closed"))
            for adr, path, disposition in paths:
                with self.subTest(path=path):
                    repo.add_markdown(path, closure_document(path, adr, "Proposed", f"{adr}X"))
                    with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                        self.validate(repo)
                    repo.add_markdown(path, closure_document(path, adr, disposition))
            path = "docs/adr/README.md"
            for body in (closure_document(path, "ADR-0027", "Accepted", "XADR-0027"), closure_document(path, "ADR-0027", "Accepted", "NOT ADR-0027"), closure_document(path, "ADR-0027", "Accepted") + closure_document(path, "ADR-0027", "Proposed")):
                repo.add_markdown(path, body)
                with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                    self.validate(repo)
            repo.add_markdown(path, closure_document(path, "ADR-0027", "Accepted"))

    def test_closure_tables_reject_wrong_link_and_accepted_in_wrong_column(self) -> None:
        with temporary_index_fixture() as repo:
            path = "docs/adr/README.md"
            repo.add_markdown(path, closure_document(path, "ADR-0027", "Accepted", link_target="https://example.invalid/ADR-0027"))
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                self.validate(repo)

    def test_each_table_role_rejects_a_non_repository_link_target(self) -> None:
        rows = (
            ("docs/adr/README.md", "ADR-0027", "Accepted"),
            ("docs/decisions/DECISION_LOG.md", "ADR-0027", "Accepted"),
            ("docs/decisions/OPEN_QUESTIONS.md", "ADR-0027", "**Resolved**"),
            ("docs/desktop/adr/README.md", "ADR-0015", "Accepted"),
            ("docs/desktop/decisions/DECISION_LOG.md", "ADR-0015", "Accepted"),
            ("docs/desktop/decisions/OPEN_QUESTIONS.md", "ADR-0015", "Closed"),
        )
        for path, adr, state in rows:
            with self.subTest(path=path), temporary_index_fixture() as repo:
                repo.add_markdown(path, closure_document(path, adr, state, link_target=f"https://example.invalid/{adr}"))
                with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                    self.validate(repo)

    def test_open_question_allows_an_unrelated_row_with_same_adr_reference(self) -> None:
        with temporary_index_fixture() as repo:
            path = "docs/decisions/OPEN_QUESTIONS.md"
            body = closure_document(path, "ADR-0027", "**Resolved**")
            body += "| OQ-999 | Other question | Other context | 2026-08-10 | **Resolved** | [ADR-0027](../adr/ADR-0027-v1-platform-scope.md) |\n"
            repo.add_markdown(path, body)
            self.assertEqual(len(self.validate(repo)), 7)
        with temporary_index_fixture() as repo:
            path = "docs/decisions/DECISION_LOG.md"
            repo.add_markdown(path, closure_document(path, "ADR-0027", "Rejected"))
            body = (repo.root / path).read_text(encoding="utf-8").replace("Rejected shared", "Accepted shared")
            repo.add_markdown(path, body)
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                self.validate(repo)

    def test_decision_logs_accept_historical_proposed_then_accepted(self) -> None:
        with temporary_index_fixture() as repo:
            for path, adr in (("docs/decisions/DECISION_LOG.md", "ADR-0027"), ("docs/desktop/decisions/DECISION_LOG.md", "ADR-0015")):
                repo.add_markdown(path, decision_log_document(path, adr, ("Proposed", "Accepted")))
            self.assertEqual(len(self.validate(repo)), 7)

    def test_decision_logs_reject_duplicate_or_conflicting_terminal_rows(self) -> None:
        for states in (("Accepted", "Accepted"), ("Rejected", "Accepted"), ("Accepted", "Rejected"), ("Accepted", "Proposed"), ("Accepted", "Reopened")):
            with self.subTest(states=states), temporary_index_fixture() as repo:
                path = "docs/decisions/DECISION_LOG.md"
                repo.add_markdown(path, decision_log_document(path, "ADR-0027", states))
                with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                    self.validate(repo)

    def test_decision_log_rejects_open_terminal_state(self) -> None:
        self._assert_runtime_log_state_rejected("Open")

    def test_decision_log_rejects_pending_terminal_state(self) -> None:
        self._assert_runtime_log_state_rejected("Pending")

    def test_decision_log_rejects_not_accepted_terminal_state(self) -> None:
        self._assert_runtime_log_state_rejected("Not accepted")

    def test_decision_log_rejects_rejected_terminal_state(self) -> None:
        self._assert_runtime_log_state_rejected("Rejected")

    def _assert_runtime_log_state_rejected(self, state: str) -> None:
        with temporary_index_fixture() as repo:
            path = "docs/decisions/DECISION_LOG.md"
            repo.add_markdown(path, decision_log_document(path, "ADR-0027", (state,)))
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"):
                self.validate(repo)

    def test_rejects_laundering_and_whitespace_reason(self) -> None:
        with temporary_index_fixture() as repo:
            registry, *_ = valid_claim_registry(repo)
            laundering = changed(registry, lambda value: value["claims"][-1].update(disposition="non_normative_exclusion", replacement_adr_ids=[]))
            blank = changed(registry, lambda value: value["claims"][0].__setitem__("reason", " \t "))
            for altered in (laundering, blank):
                with self.subTest(), self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_REGISTRY|CLAIM_DELTA_DISPOSITION_MISMATCH"):
                    self.validate(repo, registry=altered)

    def test_accepts_arbitrary_claims_and_rejects_omitted_occurrences(self) -> None:
        with temporary_index_fixture() as repo:
            registry, base, delta, _ = valid_claim_registry(repo)
            path, literal = "docs/notes/ARBITRARY.md", "arbitrary fixture claim"
            repo.add_markdown(path, literal)
            registry = changed(registry, lambda value: value["claims"].append({"claim_id": "ARBITRARY_CLAIM", "literal_needles": [literal], "expected_paths": [path], "disposition": "non_normative_exclusion", "replacement_adr_ids": [], "owner": "shared", "reason": "A generic closed fixture claim."}))
            registry = changed(registry, lambda value: value["claims"].sort(key=lambda item: item["claim_id"]))
            delta = changed(delta, lambda value: value["rows"].append({"path": path, "classification": "non_normative_exclusion", "content_sha256": "8" * 64}))
            delta = changed(delta, lambda value: value["rows"].sort(key=lambda item: item["path"]))
            registry, base, delta, composed = with_lineage(registry, base, delta)
            self.assertEqual(len(self.validate(repo, registry, base, delta, composed)), 8)
            omitted = changed(registry, lambda value: value["claims"].pop(0))
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_LINEAGE_MISMATCH"):
                self.validate(repo, omitted, base, delta, composed)

    def test_accepts_task_three_generic_fixture_when_universe_matches(self) -> None:
        documents = {"docs/00-foundation/README.md": "foundation\n", "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md": "fixture-only platform scope\n"}
        with temporary_index_fixture(documents) as repo:
            self.assertEqual(len(validate_claim_registry(repo.root, *task3_claim_registry())), 1)

    def test_sanitizes_hostile_environment_and_rejects_swaps_and_symlinks(self) -> None:
        with temporary_index_fixture() as repo:
            with mock.patch.dict(os.environ, {"GIT_DIR": "/dev/null", "GIT_WORK_TREE": "/", "GIT_INDEX_FILE": "/dev/null"}):
                self.assertEqual(len(self.validate(repo)), 7)
            repo.unstaged_swap("docs/notes/MACOS.md", "macOS production Developer ID\nunstaged\n")
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_TRACKED_DOCUMENT_UNSTAGED"):
                self.validate(repo)
        with temporary_index_fixture() as repo:
            repo.external_leaf_symlink("docs/notes/MACOS.md")
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_TRACKED_PATH_UNSAFE"):
                self.validate(repo)
        with temporary_index_fixture() as repo:
            repo.external_parent_symlink()
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_TRACKED_PATH_UNSAFE"):
                self.validate(repo)
        with temporary_index_fixture() as left, temporary_index_fixture() as right:
            self.assertEqual((len(self.validate(left)), len(self.validate(right))), (7, 7))

    def test_byte_exact_late_paths_and_regenerated_lineage(self) -> None:
        with temporary_index_fixture() as repo:
            registry, base, delta, _ = valid_claim_registry(repo)
            for path, body in (("docs/release/CASE.md", "windows server 2025 is the v1 production target."), ("notes/NFC.markdown", "Window\u0301s Server 2025 is the v1 production target.")):
                repo.add_markdown(path, body)
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_TRACKED_PATH_SET_MISMATCH"):
                self.validate(repo)
            path = "docs/release/LATE.md"; literal = "Windows Server 2025 is the v1 production target."
            repo.add_markdown(path, literal)
            registry = changed(registry, lambda value: value["claims"][-1]["expected_paths"].append(path))
            delta = changed(delta, lambda value: value["rows"].append({"path": path, "classification": "superseded", "content_sha256": "9" * 64}))
            registry, base, delta, composed = with_lineage(registry, base, delta)
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_TRACKED_PATH_SET_MISMATCH"):
                self.validate(repo, registry, base, delta, composed)
        with temporary_index_fixture() as repo:
            registry, base, delta, _ = valid_claim_registry(repo)
            repo.add_markdown("docs/release/LATE.md", "Windows Server 2025 is the v1 production target.")
            registry = changed(registry, lambda value: value["claims"][-1]["expected_paths"].append("docs/release/LATE.md"))
            delta = changed(delta, lambda value: value["rows"].append({"path": "docs/release/LATE.md", "classification": "superseded", "content_sha256": "9" * 64}))
            registry, base, delta, composed = with_lineage(registry, base, delta)
            self.assertEqual(len(self.validate(repo, registry, base, delta, composed)), 8)

    def test_literal_matching_is_case_and_unicode_byte_exact(self) -> None:
        with temporary_index_fixture() as repo:
            registry, *_ = valid_claim_registry(repo)
            repo.add_markdown("docs/notes/NON_NORMATIVE.md", "cafe\u0301\n")
            registry = changed(registry, lambda value: value["claims"][0].__setitem__("literal_needles", ["café"]))
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_EXPECTED_PATH_SET_MISMATCH"):
                self.validate(repo, registry=registry)
        with temporary_index_fixture() as repo:
            repo.add_markdown("docs/notes/NATIVE.md", "NATIVE THREE-PLATFORM PRODUCTION\n")
            with self.assertRaisesRegex(ClaimMigrationFailure, "CLAIM_EXPECTED_PATH_SET_MISMATCH"):
                self.validate(repo)

    def test_overlay_lineage_matches_mapping_contract(self) -> None:
        registry, base, delta, composed = overlap_vector()
        _lineage(
            json.loads(registry), json.loads(composed),
            _rows(base, "gocode.rc0.fixture-base-document-universe/1"),
            _rows(delta, "gocode.rc0.fixture-classified-delta/1"), base, delta,
        )
        result = mapping_lineage(valid_mapping_fixture().adjunct_trust, registry, base, delta, composed)
        self.assertEqual(
            result[1:],
            (hashlib.sha256(base).hexdigest(), hashlib.sha256(delta).hexdigest(),
             loads_canonical(composed)["composed_document_universe_payload_sha256"]),
        )


if __name__ == "__main__":
    unittest.main()
