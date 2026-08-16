"""Exact per-registry ADR identity validation."""
from __future__ import annotations
from pathlib import Path
import re


ADR_DIRECTORIES = ("docs/adr", "docs/desktop/adr")
ADR_FILE = re.compile(r"ADR-(\d{4})-(.+)\.md$")
ADR_TITLE = re.compile(r'^title: "ADR-(\d{4}):', re.MULTILINE)
ADR_HEADING = re.compile(r"^# ADR-(\d{4}):", re.MULTILINE)
ADR_ROW = re.compile(r"\| \[ADR-(\d{4})\]\((ADR-\d{4}-[^)]+\.md)\) \|")


def _adr_document_id(path: Path):
    match = ADR_FILE.fullmatch(path.name)
    if match is None:
        return None
    if path.name == "ADR-0000-template.md":
        return "0000", "0000", "0000"
    text = path.read_text(encoding="utf-8")
    title = ADR_TITLE.search(text)
    heading = ADR_HEADING.search(text)
    return match.group(1), title.group(1) if title else None, heading.group(1) if heading else None


def validate_adr_identity(root: Path) -> list[str]:
    diagnostics = []
    for relative in ADR_DIRECTORIES:
        directory = root / relative
        if not directory.is_dir():
            diagnostics.append(f"ADR_REGISTRY_MISSING:{relative}")
            continue
        ids = {}
        for path in sorted(directory.glob("ADR-*.md")):
            value = _adr_document_id(path)
            if value is None:
                diagnostics.append(f"ADR_FILENAME_INVALID:{relative}/{path.name}")
                continue
            filename_id, title_id, heading_id = value
            if title_id != filename_id or heading_id != filename_id:
                diagnostics.append(f"ADR_ID_MISMATCH:{relative}/{path.name}")
            if filename_id in ids:
                diagnostics.append(f"ADR_ID_DUPLICATE:{relative}:ADR-{filename_id}")
            ids[filename_id] = path.name
        try:
            rows = ADR_ROW.findall((directory / "README.md").read_text(encoding="utf-8"))
        except OSError:
            diagnostics.append(f"ADR_REGISTRY_MISSING:{relative}/README.md")
            continue
        listed = {}
        for row_id, filename in rows:
            if row_id in listed or ADR_FILE.fullmatch(filename) is None or filename_id_from_name(filename) != row_id:
                diagnostics.append(f"ADR_REGISTRY_DUPLICATE:{relative}:ADR-{row_id}")
            listed[row_id] = filename
        for adr_id, filename in ids.items():
            if listed.get(adr_id) != filename:
                diagnostics.append(f"ADR_REGISTRY_MISMATCH:{relative}:ADR-{adr_id}")
        for adr_id in set(listed) - set(ids):
            diagnostics.append(f"ADR_REGISTRY_UNKNOWN:{relative}:ADR-{adr_id}")
    return sorted(set(diagnostics))


def filename_id_from_name(name: str) -> str | None:
    match = ADR_FILE.fullmatch(name)
    return match.group(1) if match else None
