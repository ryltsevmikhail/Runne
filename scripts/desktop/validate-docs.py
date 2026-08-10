#!/usr/bin/env python3
"""Validate GOCODE UI Markdown documentation."""

from pathlib import Path
import hashlib
import json
import re
import sys

from capability_manifest_impl.validation import validate_repository

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "desktop"
STRICT = "--strict" in sys.argv
errors: list[str] = []
warnings: list[str] = []

required_front_matter = {
    "title", "status", "document_type", "source_status",
    "created", "updated", "owners",
}
allowed_statuses = {
    "draft", "review", "ready", "deprecated",
    "proposed", "accepted", "superseded", "rejected",
}
allowed_source_statuses = {
    "Observed", "Reported", "Inferred", "Target", "Decision",
    "Hypothesis", "Open Question", "Mixed",
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
    status_match = re.search(r'^status:\s*"?([^"\n]+)"?', front_matter, re.MULTILINE)
    source_match = re.search(
        r'^source_status:\s*"?([^"\n]+)"?', front_matter, re.MULTILINE
    )
    if status_match and status_match.group(1).strip() not in allowed_statuses:
        errors.append(f"{rel}: unsupported status {status_match.group(1).strip()}")
    if (
        source_match
        and source_match.group(1).strip() not in allowed_source_statuses
    ):
        errors.append(
            f"{rel}: unsupported source_status {source_match.group(1).strip()}"
        )

# JSON schemas must be valid draft 2020-12 documents.
for path in sorted(DOCS.rglob("*.json")):
    rel = path.relative_to(ROOT)
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{rel}: invalid JSON: {exc}")
        continue
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{rel}: wrong or missing $schema")
    if not schema.get("$id") or not schema.get("title"):
        errors.append(f"{rel}: schema requires $id and title")

link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+\.md(?:#[^)]+)?)\)")
for path in sorted(DOCS.rglob("*.md")):
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

ignored_generated_dirs = {"node_modules", "target", "dist", "coverage", ".vite"}
for path in sorted(DOCS.rglob("*")):
    relative_parts = path.relative_to(ROOT).parts
    if (
        path.is_file()
        and relative_parts[0] != "upstream"
        and not any(part.startswith(".") for part in relative_parts)
        and not ignored_generated_dirs.intersection(relative_parts)
    ):
        if path.stat().st_size == 0:
            errors.append(f"{path.relative_to(ROOT)}: empty file")

if "bc6cf79fda5b13c937dbae92bdf2d912a987eeb0" not in (
    DOCS / "00-foundation/UPSTREAM_BASELINES.md"
).read_text(encoding="utf-8"):
    errors.append("OpenSail baseline is missing or changed")

if "51ab86bab6c43186181e0ca97261c8406a1e9625" not in (
    DOCS / "00-foundation/UPSTREAM_BASELINES.md"
).read_text(encoding="utf-8"):
    errors.append("Paseo baseline is missing or changed")

donor_files = {
    "upstream/desktop/opensail/LICENSE": (
        "3fa29bb36301035ba3aa3c67ba603e154083785e28c592843648b7fe33515c94"
    ),
    "upstream/desktop/opensail/NOTICE": (
        "ffef42e4c11aff93765f97c73f2c74907b33c31776cc9fe3bb406e9a2ec4fb55"
    ),
    "upstream/desktop/opensail/THIRD-PARTY-NOTICES.md": (
        "f6813d36e568bcfeddc3e408da87e334fd0eac58dd1837b3d3e9d8821e2055a4"
    ),
    "upstream/desktop/paseo/LICENSE": (
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

donor_trees = {
    "upstream/desktop/opensail": (
        3104,
        "3d395652ebcbb6ce31c717302e7edcf08a24eb2b5d8f4399a8791d41c6b23dda",
    ),
    "upstream/desktop/paseo": (
        3287,
        "91a56d79ab494d2612f7de6c81b336e8662d0b94201dc8bd2eb5e27974491554",
    ),
}
for relative_dir, (expected_count, expected_tree_digest) in donor_trees.items():
    donor_root = ROOT / relative_dir
    files = sorted(
        (
            path for path in donor_root.rglob("*")
            if path.is_file() and not path.is_symlink()
        ),
        key=lambda path: path.relative_to(donor_root).as_posix(),
    )
    if len(files) != expected_count:
        errors.append(
            f"{relative_dir}: expected {expected_count} files, got {len(files)}"
        )
        continue
    inventory = hashlib.sha256()
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(donor_root).as_posix()
        inventory.update(f"{digest}  ./{relative}\n".encode())
    if inventory.hexdigest() != expected_tree_digest:
        errors.append(f"{relative_dir}: donor snapshot tree digest changed")

# Canonical requirement registry must be fully represented in traceability.
requirement_pattern = re.compile(r"\bREQ-[A-Z]+-\d{3}\b")
canonical_requirements = requirement_pattern.findall(
    (DOCS / "00-foundation/REQUIREMENTS.md").read_text(encoding="utf-8")
)
if len(canonical_requirements) != len(set(canonical_requirements)):
    errors.append("Canonical requirements contain duplicate IDs")
traced_requirements = set(
    requirement_pattern.findall(
        (DOCS / "matrices/REQUIREMENTS_TRACEABILITY.md").read_text(
            encoding="utf-8"
        )
    )
)
missing_trace = sorted(set(canonical_requirements) - traced_requirements)
if missing_trace:
    errors.append(f"Requirements missing traceability: {', '.join(missing_trace)}")

# Every ADR file must have a unique ID and be listed in the ADR index.
adr_files = sorted((DOCS / "adr").glob("ADR-*.md"))
adr_ids = [path.name.split("-", 2)[:2] for path in adr_files]
normalized_adr_ids = ["-".join(parts) for parts in adr_ids]
if len(normalized_adr_ids) != len(set(normalized_adr_ids)):
    errors.append("Duplicate ADR IDs")
adr_index = (DOCS / "adr/README.md").read_text(encoding="utf-8")
for path in adr_files:
    if path.name not in adr_index:
        errors.append(f"docs/adr/README.md: missing {path.name}")

# Top-level documentation sections require a README entry point.
for path in sorted(DOCS.iterdir()):
    if path.is_dir() and path.name not in {"decisions"}:
        if not (path / "README.md").is_file():
            errors.append(f"docs/{path.name}: missing README.md")

errors.extend(validate_repository(ROOT))

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
