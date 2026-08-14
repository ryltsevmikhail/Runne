"""Strict accepted-ADR status parser for fixture-only platform joins."""

from __future__ import annotations

import re
from typing import Literal


class GovernanceStatusFailure(ValueError):
    pass


_FRONT = re.compile(r"\A---\n(?P<front>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)
_TITLE = re.compile(r"(?m)^# (?P<id>ADR-\d{4}):[^\n]+$")
_RUNTIME = re.compile(r"(?m)^\*\*Status:\*\* accepted$")
_DESKTOP = re.compile(r"(?m)^Accepted\.$")
_DIGEST = re.compile(r"(?m)^- `(?P<name>shared_decision_(?:payload|schema)_sha256)`: `(?P<digest>[0-9a-f]{64})`$")


def _fail() -> None:
    raise GovernanceStatusFailure("ADR_STATUS_INVALID")


def _front_value(front: str, key: str) -> str | None:
    values = re.findall(rf"(?m)^{re.escape(key)}: ([^\n]+)$", front)
    return values[0] if len(values) == 1 else None


def parse_accepted_adr(
    raw: bytes, expected_adr_id: str, expected_owner_domain: Literal["runtime", "desktop"],
) -> None:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise GovernanceStatusFailure("ADR_UTF8_INVALID") from error
    match = _FRONT.fullmatch(text)
    if match is None or text.count("\n---\n") != 1:
        _fail()
    front, body = match.group("front"), match.group("body")
    owner = "gocode-runtime" if expected_owner_domain == "runtime" else "gocode-desktop"
    if _front_value(front, "status") != "ready" or front.count("owners:") != 1:
        _fail()
    owners = re.findall(r"(?m)^  - ([^\n]+)$", front)
    if owners != [owner] or _TITLE.findall(body) != [expected_adr_id]:
        _fail()
    visible = _RUNTIME.findall(body) if expected_owner_domain == "runtime" else _DESKTOP.findall(body)
    if len(visible) != 1:
        _fail()
    if re.search(r"(?im)\b(not\s+accepted|superseded|proposed)\b", body):
        _fail()


def accepted_adr_digests(
    raw: bytes, expected_adr_id: str, expected_owner_domain: Literal["runtime", "desktop"],
) -> tuple[str, str]:
    parse_accepted_adr(raw, expected_adr_id, expected_owner_domain)
    text = raw.decode("utf-8", "strict")
    values = _DIGEST.findall(text)
    if len(values) != 2 or {name for name, _ in values} != {
        "shared_decision_payload_sha256", "shared_decision_schema_sha256",
    }:
        _fail()
    return dict(values)["shared_decision_payload_sha256"], dict(values)["shared_decision_schema_sha256"]
