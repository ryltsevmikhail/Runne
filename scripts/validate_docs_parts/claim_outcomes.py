"""Bounded claim lexer and finite outcome grammar for ADR-0025 documents."""

from __future__ import annotations

import unicodedata


MAX_DOCUMENT_CHARS = 262_144
MAX_TOKENS = 32_768
MAX_TOKEN_CHARS = 128
SUBJECTS = {
    "productionqualification": "PRODUCTION_QUALIFICATION",
    "release": "RELEASE_PASS",
    "signing": "SIGNING_PASS",
    "notarization": "NOTARIZATION_PASS",
    "publication": "PUBLICATION_PASS",
}
OUTCOMES = frozenset(
    {
        "complete",
        "completed",
        "approved",
        "succeeded",
        "authorized",
        "pass",
        "passed",
        "passes",
        "successful",
    }
)
CONNECTORS = frozenset({"is", "was", "has", "been", "now"})
MENTION_NEEDLES = {
    "RC0_QUALIFIED": "rc0qualified",
    "CANDIDATE_PASS": "candidatepass",
    "PRODUCTION_QUALIFICATION": "productionqualificationpass",
    "RELEASE_PASS": "releasepass",
    "SIGNING_PASS": "signingpass",
    "NOTARIZATION_PASS": "notarizationpass",
    "PUBLICATION_PASS": "publicationpass",
}
HARD_BOUNDARIES = frozenset(".!?;()。！？")


class ClaimParseError(ValueError):
    """A document exceeds a parser bound and cannot be classified safely."""


class ParsedClaims:
    """Immutable parser result without dynamic-loader registration requirements."""

    __slots__ = ("mentions", "positive_outcomes")

    def __init__(self, mentions: frozenset[str], outcomes: frozenset[str]):
        self.mentions = mentions
        self.positive_outcomes = outcomes


def _without_code(text: str) -> str:
    """Blank fenced and inline code while retaining line structure."""
    output: list[str] = []
    fenced = False
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            fenced = not fenced
            output.append("\n" if line.endswith("\n") else "")
            continue
        if fenced:
            output.append("\n" if line.endswith("\n") else "")
            continue
        inline = False
        for char in line:
            if char == "`":
                inline = not inline
                output.append(" ")
            elif inline and char != "\n":
                output.append(" ")
            else:
                output.append(char)
    return "".join(output)


def _tokens_normalized(normalized: str) -> tuple[str, ...]:
    if len(normalized) > MAX_DOCUMENT_CHARS:
        raise ClaimParseError("CLAIM_DOCUMENT_TOO_LARGE")
    tokens: list[str] = []
    current: list[str] = []
    for char in normalized:
        if char.isalnum():
            current.append(char)
            if len(current) > MAX_TOKEN_CHARS:
                raise ClaimParseError("CLAIM_TOKEN_TOO_LARGE")
        elif current:
            tokens.append("".join(current))
            current = []
            if len(tokens) > MAX_TOKENS:
                raise ClaimParseError("CLAIM_TOO_MANY_TOKENS")
    if current:
        tokens.append("".join(current))
    if len(tokens) > MAX_TOKENS:
        raise ClaimParseError("CLAIM_TOO_MANY_TOKENS")
    return tuple(tokens)


def _tokens(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return _tokens_normalized(normalized)


def _consume_joined(tokens: tuple[str, ...], start: int, choices: set[str] | frozenset[str]):
    """Consume at most three adjacent pieces that concatenate to an exact choice."""
    combined = ""
    for end in range(start, min(start + 3, len(tokens))):
        combined += tokens[end]
        if combined in choices:
            return combined, end + 1
        if not any(choice.startswith(combined) for choice in choices):
            break
    return None


def _positive_outcomes(tokens: tuple[str, ...]) -> frozenset[str]:
    detected: set[str] = set()
    subject_choices = set(SUBJECTS)
    for start in range(len(tokens)):
        subject = _consume_joined(tokens, start, subject_choices)
        if subject is None:
            continue
        if subject[0] == "release" and start != 0:
            continue
        cursor = subject[1]
        connectors = 0
        while cursor < len(tokens) and tokens[cursor] in CONNECTORS and connectors < 3:
            cursor += 1
            connectors += 1
        outcome = _consume_joined(tokens, cursor, OUTCOMES)
        if outcome is not None:
            detected.add(SUBJECTS[subject[0]])
    return frozenset(detected)


def _mention_ids(text: str) -> frozenset[str]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    if len(normalized) > MAX_DOCUMENT_CHARS:
        raise ClaimParseError("CLAIM_DOCUMENT_TOO_LARGE")
    compact = "".join(char for char in normalized if not char.isspace() and char not in "_-")
    return frozenset(
        claim_id for claim_id, needle in MENTION_NEEDLES.items() if needle in compact
    )


def _prose_clauses(text: str) -> tuple[tuple[str, ...], ...]:
    normalized = unicodedata.normalize("NFKC", _without_code(text)).casefold()
    if len(normalized) > MAX_DOCUMENT_CHARS:
        raise ClaimParseError("CLAIM_DOCUMENT_TOO_LARGE")
    clauses, start = [], 0
    for index, char in enumerate(normalized):
        if char in HARD_BOUNDARIES:
            clauses.append(_tokens_normalized(normalized[start:index]))
            start = index + 1
    clauses.append(_tokens_normalized(normalized[start:]))
    return tuple(clause for clause in clauses if clause)


def parse_claims(text: str) -> ParsedClaims:
    """Parse bounded exact mentions and natural positive outcome records."""
    outcomes: set[str] = set()
    for clause in _prose_clauses(text):
        outcomes.update(_positive_outcomes(clause))
    return ParsedClaims(_mention_ids(text), frozenset(outcomes))
