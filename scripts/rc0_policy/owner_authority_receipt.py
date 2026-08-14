"""Fail-closed shim for the superseded legacy G1 receipt boundary."""

from __future__ import annotations


SUPERSEDED_G1_UNSUPPORTED = "SUPERSEDED_G1_UNSUPPORTED"


class G1Failure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _unsupported() -> None:
    raise G1Failure(SUPERSEDED_G1_UNSUPPORTED)


def verify_g1_authority_receipt(*args: object, **kwargs: object) -> None:
    _unsupported()


def verify_owner_authority_receipt(*args: object, **kwargs: object) -> None:
    _unsupported()


def require_production_g1(*args: object, **kwargs: object) -> None:
    _unsupported()
