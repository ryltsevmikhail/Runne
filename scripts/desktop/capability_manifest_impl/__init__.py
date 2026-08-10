"""Deterministic validation and scoring for the Desktop v1 capability registry."""

from .scoring import Evaluation, QualificationContext, evaluate
from .validation import validate_definition, validate_repository, validate_status

__all__ = [
    "Evaluation",
    "QualificationContext",
    "evaluate",
    "validate_definition",
    "validate_repository",
    "validate_status",
]
