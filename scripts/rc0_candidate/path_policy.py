"""Closed artifact path and URL policy for candidate evidence."""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

_CREDENTIAL_KEYS = (
    "access_token", "api_key", "apikey", "authorization", "credential",
    "password", "passwd", "private_key", "secret", "signature", "token",
)
_CREDENTIAL_PREFIXES = (
    "-----begin private key", "bearer ", "basic ", "ghp_", "github_pat_", "sk-",
)
_AUTHORITY_SUBSTRINGS = ("verification", "report", "declaration", "verdict")
_CANONICAL_EVIDENCE_NAMES = {"source-gate-results.json"}
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")


def validate_https_url(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return ("URL must be non-empty control-free text",)
    if "%" in value or "\\" in value:
        return ("URL encoded separators and backslashes are forbidden",)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ("URL is malformed",)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or _HOST.fullmatch(parsed.hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or any(segment in (".", "..") for segment in parsed.path.split("/"))
    ):
        return ("URL is outside the strict credential-free HTTPS profile",)
    return ()


def validate_artifact_path(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ("artifact path must be text",)
    parts = value.split("/")
    lowered = [part.casefold() for part in parts]
    folded = [
        "".join(
            char for char in unicodedata.normalize("NFKD", part.casefold())
            if unicodedata.category(char) != "Mn"
        )
        for part in parts
    ]
    basename = lowered[-1] if lowered else ""
    if lowered[:2] == ["docs", "evidence"]:
        return ("artifact path enters the evidence namespace",)
    if any(part in ("logs", "reports") for part in lowered) or basename.endswith(".log"):
        return ("artifact path enters a log or report namespace",)
    forbidden_substring = any(
        item in part for part in folded for item in _AUTHORITY_SUBSTRINGS
    )
    gate_output = (
        any("gate" in part for part in folded)
        and basename not in _CANONICAL_EVIDENCE_NAMES
    )
    if forbidden_substring or gate_output:
        return ("artifact path resembles an authority output",)
    return ()


def evidence_value_diagnostics(value: Any, path: str = "$", field: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.casefold()
            if any(token in lowered for token in _CREDENTIAL_KEYS):
                errors.append(f"credential-shaped field is forbidden at {path}.{key}")
            errors.extend(evidence_value_diagnostics(item, f"{path}.{key}", key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(evidence_value_diagnostics(item, f"{path}[{index}]", field))
    elif isinstance(value, str):
        lowered = value.casefold()
        if lowered.startswith(_CREDENTIAL_PREFIXES):
            errors.append(f"credential material is forbidden at {path}")
        url_field = field in ("documentNamespace", "downloadLocation") or field.casefold().endswith(("url", "uri"))
        if field == "downloadLocation" and value in ("NONE", "NOASSERTION"):
            url_field = False
        if url_field:
            errors.extend(f"{path}: {item}" for item in validate_https_url(value))
        elif "://" in value and validate_https_url(value):
            errors.append(f"noncanonical URL value is forbidden at {path}")
    return errors
