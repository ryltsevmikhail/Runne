"""Closed contracts for macOS signing preparation."""

from .models import CommandResult, CommandSpec, FailureCode, SigningProfile, SigningRequest
from .policy import map_tool_status, parse_profile
from .workflow import normalize_outcome, prepare_signing

__all__ = (
    "CommandResult",
    "CommandSpec",
    "FailureCode",
    "SigningProfile",
    "SigningRequest",
    "map_tool_status",
    "normalize_outcome",
    "parse_profile",
    "prepare_signing",
)
