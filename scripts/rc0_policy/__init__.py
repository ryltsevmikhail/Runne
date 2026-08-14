"""Non-authoritative RC0 fixture parsing and schema diagnostics."""

from .canonical import StrictJSONError, canonical_bytes, loads_canonical
from .model import FixtureValidation, FixtureValidationError, validate_fixture

__all__ = [
    "FixtureValidation",
    "FixtureValidationError",
    "StrictJSONError",
    "canonical_bytes",
    "loads_canonical",
    "validate_fixture",
]
