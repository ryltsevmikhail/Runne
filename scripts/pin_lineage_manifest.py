#!/usr/bin/env python3
"""Parse the canonical evidence manifest without Markdown shadow fields."""

from __future__ import annotations

import re


_HEADING = re.compile(r"^## Evidence manifest[ \t]*$", re.MULTILINE)
_MANIFEST = re.compile(
    r"^## Evidence manifest[ \t]*\n(?:[ \t]*\n)*^```yaml[ \t]*\n"
    r"(?P<body>.*?)^```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9_]*):[ \t]*(.*)$", re.MULTILINE)


def require_manifest_fields(evidence: str, related: tuple[str, ...]) -> dict[str, str]:
    """Return unique canonical fields and reject matching fields elsewhere."""
    if len(_HEADING.findall(evidence)) != 1:
        raise SystemExit("evidence requires exactly one Evidence manifest heading")
    manifests = list(_MANIFEST.finditer(evidence))
    if len(manifests) != 1:
        raise SystemExit("evidence requires exactly one canonical YAML manifest")
    manifest = manifests[0]
    body = manifest.group("body")
    fields: dict[str, str] = {}
    for item in _FIELD.finditer(body):
        name, value = item.groups()
        if name in fields:
            raise SystemExit(f"duplicate manifest field: {name}")
        fields[name] = value
    for item in _FIELD.finditer(evidence):
        if item.group(1) in related and not (
            manifest.start("body") <= item.start() < manifest.end("body")
        ):
            raise SystemExit(f"evidence field appears outside canonical manifest: {item.group(1)}")
    return fields
