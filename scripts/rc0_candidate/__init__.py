"""Local, non-authoritative RC0 candidate fixture helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FixtureLocalInputsSummary:
    """A synthetic local-input marker; never a qualification result."""

    status: str
    blocked_reason: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {"status": self.status}
        if self.blocked_reason is not None:
            result["blocked_reason"] = self.blocked_reason
        return result
