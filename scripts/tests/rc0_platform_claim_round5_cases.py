"""Round-five full-validator regressions for Task 8 closure tables."""

from __future__ import annotations

from scripts.rc0_policy.claim_migration import ClaimMigrationFailure
from scripts.tests.rc0_platform_claim_support import (
    decision_log_document,
    temporary_index_fixture,
)


class ClaimClosureRound5Cases:
    def test_decision_logs_reject_pending_then_accepted(self) -> None:
        for path, adr in (
            ("docs/decisions/DECISION_LOG.md", "ADR-0027"),
            ("docs/desktop/decisions/DECISION_LOG.md", "ADR-0015"),
        ):
            with self.subTest(path=path), temporary_index_fixture() as repo:
                repo.add_markdown(
                    path, decision_log_document(path, adr, ("Pending", "Accepted"))
                )
                with self.assertRaisesRegex(
                    ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"
                ):
                    self.validate(repo)

    def test_desktop_log_rejects_state_tokens_after_accepted(self) -> None:
        path = "docs/desktop/decisions/DECISION_LOG.md"
        canonical = "Accepted shared v1 platform scope"
        for contradiction in (
            "Open",
            "Rejected",
            "Not accepted",
            "Pending",
            "Proposed",
            "Reopened",
        ):
            with self.subTest(contradiction=contradiction), temporary_index_fixture() as repo:
                body = decision_log_document(path, "ADR-0015", ("Accepted",))
                repo.add_markdown(
                    path, body.replace(canonical, f"{canonical}; {contradiction}", 1)
                )
                with self.assertRaisesRegex(
                    ClaimMigrationFailure, "CLAIM_ADR_CLOSURE_MISMATCH"
                ):
                    self.validate(repo)
