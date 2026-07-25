#!/usr/bin/env python3
"""Validate GOCODE UI Markdown documentation."""

from pathlib import Path
import hashlib
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
STRICT = "--strict" in sys.argv
errors: list[str] = []
warnings: list[str] = []

required_front_matter = {
    "title", "status", "document_type", "source_status",
    "created", "updated", "owners",
}

for path in sorted(DOCS.rglob("*.md")):
    content = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT)
    if not content.startswith("---\n"):
        errors.append(f"{rel}: missing YAML front matter")
        continue
    try:
        front_matter = content.split("---\n", 2)[1]
    except IndexError:
        errors.append(f"{rel}: malformed YAML front matter")
        continue
    keys = {
        match.group(1)
        for match in re.finditer(r"^([a-z_]+):", front_matter, re.MULTILINE)
    }
    missing = sorted(required_front_matter - keys)
    if missing:
        errors.append(f"{rel}: missing front matter keys: {', '.join(missing)}")

link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+\.md(?:#[^)]+)?)\)")
for path in sorted(ROOT.rglob("*.md")):
    relative_parts = path.relative_to(ROOT).parts
    if (
        any(part.startswith(".") for part in relative_parts)
        or relative_parts[0] == "upstream"
    ):
        continue
    content = path.read_text(encoding="utf-8")
    for target in link_pattern.findall(content):
        if target.startswith(("http://", "https://")):
            continue
        file_target = target.split("#", 1)[0]
        resolved = (path.parent / file_target).resolve()
        if not resolved.exists():
            errors.append(
                f"{path.relative_to(ROOT)}: broken link -> {file_target}"
            )

for path in sorted(ROOT.rglob("*")):
    relative_parts = path.relative_to(ROOT).parts
    if (
        path.is_file()
        and relative_parts[0] != "upstream"
        and not any(part.startswith(".") for part in relative_parts)
    ):
        if path.stat().st_size == 0:
            errors.append(f"{path.relative_to(ROOT)}: empty file")

if "bc6cf79fda5b13c937dbae92bdf2d912a987eeb0" not in (
    ROOT / "docs/00-foundation/UPSTREAM_BASELINES.md"
).read_text(encoding="utf-8"):
    errors.append("OpenSail baseline is missing or changed")

if "51ab86bab6c43186181e0ca97261c8406a1e9625" not in (
    ROOT / "docs/00-foundation/UPSTREAM_BASELINES.md"
).read_text(encoding="utf-8"):
    errors.append("Paseo baseline is missing or changed")

donor_files = {
    "upstream/opensail/LICENSE": (
        "3fa29bb36301035ba3aa3c67ba603e154083785e28c592843648b7fe33515c94"
    ),
    "upstream/opensail/NOTICE": (
        "ffef42e4c11aff93765f97c73f2c74907b33c31776cc9fe3bb406e9a2ec4fb55"
    ),
    "upstream/opensail/THIRD-PARTY-NOTICES.md": (
        "f6813d36e568bcfeddc3e408da87e334fd0eac58dd1837b3d3e9d8821e2055a4"
    ),
    "upstream/paseo/LICENSE": (
        "2d29a730f15470509f7a36e63a024c2f121958471474dfcd6b272c99586fc337"
    ),
}

for relative_path, expected_digest in donor_files.items():
    donor_path = ROOT / relative_path
    if not donor_path.is_file():
        errors.append(f"{relative_path}: required donor license file is missing")
        continue
    digest = hashlib.sha256(donor_path.read_bytes()).hexdigest()
    if digest != expected_digest:
        errors.append(f"{relative_path}: donor license file was modified")

print("=== GOCODE UI Docs Validator ===")
print(f"Errors: {len(errors)}")
print(f"Warnings: {len(warnings)}")
for item in errors:
    print(f"ERROR: {item}")
for item in warnings:
    print(f"WARNING: {item}")

if errors or (STRICT and warnings):
    sys.exit(1)
print("All checks passed.")
