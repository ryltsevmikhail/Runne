#!/usr/bin/env python3
"""GOCODE Runtime documentation validator.

Usage:
    python3 scripts/validate-docs.py
    python3 scripts/validate-docs.py --strict   # также проверяет warnings
"""
import os, json, re, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM_DIR = os.path.join(BASE, "upstream", "opencode")
DOCS_DIR = os.path.join(BASE, "docs")
IMPLEMENTATION_PLANS_DIR = os.path.join(DOCS_DIR, "superpowers", "plans")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
BASELINE_DATE = "2026-07-24"
UPSTREAM_URL = "https://github.com/anomalyco/opencode"
IGNORED_TREE_NAMES = {".git", ".worktrees", "target"}
HISTORIC_SCHEMA_EXCEPTIONS = {"opencode-baseline-inventory-v1.schema.json"}

errors = []
warnings = []
strict = "--strict" in sys.argv

# ── Helpers ──────────────────────────────────────────────────────────

def err(msg):
    errors.append(msg)

def warn(msg):
    warnings.append(msg)

def walk_files(root, suffixes=None):
    """Yield repository files while excluding generated and pinned source trees."""
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in IGNORED_TREE_NAMES
            and os.path.join(current_root, directory) != UPSTREAM_DIR
        ]
        for filename in files:
            if suffixes is None or filename.endswith(suffixes):
                yield os.path.join(current_root, filename)

def is_implementation_plan(path):
    return path.startswith(IMPLEMENTATION_PLANS_DIR + os.sep)

# ── 1. JSON Schema validity ──────────────────────────────────────────

schemas_dir = os.path.join(BASE, "docs", "schemas")
for f in sorted(os.listdir(schemas_dir)):
    if not f.endswith(".json"):
        continue
    fp = os.path.join(schemas_dir, f)
    try:
        data = json.load(open(fp))
    except json.JSONDecodeError as e:
        err(f"Invalid JSON: {f} — {e}")
        continue
    if data.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        err(f"Wrong $schema in {f}: {data.get('$schema')}")
    if not data.get("$id") and f not in HISTORIC_SCHEMA_EXCEPTIONS:
        warn(f"Missing $id in {f}")
    if not data.get("title"):
        warn(f"Missing title in {f}")
    if data.get("type") != "object":
        err(f"Top-level schema must be object: {f}")
    properties = data.get("properties")
    required = data.get("required")
    if not isinstance(properties, dict) or not properties:
        err(f"Missing/non-object properties in {f}")
    if not isinstance(required, list) or not required:
        err(f"Missing/non-array required in {f}")
    elif isinstance(properties, dict):
        unknown_required = sorted(set(required) - set(properties))
        if unknown_required:
            err(f"Required fields absent from properties in {f}: {unknown_required}")
    if (
        data.get("additionalProperties") is not False
        and f not in HISTORIC_SCHEMA_EXCEPTIONS
    ):
        err(f"Top-level schema must be closed (additionalProperties=false): {f}")
    if "preliminary" in json.dumps(data).lower():
        err(f"Preliminary schema cannot be implementation input: {f}")

# ── 2. Front matter on all docs/*.md ─────────────────────────────────

for fp in walk_files(DOCS_DIR, ".md"):
    if is_implementation_plan(fp):
        continue
    head = open(fp).read(200)
    if not head.startswith("---"):
        err(f"Missing front matter: {os.path.relpath(fp, BASE)}")

# ── 2a. Structural documentation integrity ──────────────────────────

numbered_h2_re = re.compile(r"^##\s+(\d+)\.")
unresolved_marker_re = re.compile(r"\{SHA\}|\bTBD\b", re.IGNORECASE)
for fp in walk_files(DOCS_DIR, ".md"):
    if is_implementation_plan(fp) or "templates" in fp.split(os.sep):
        continue
    rel = os.path.relpath(fp, BASE)
    seen_sections = {}
    for i, line in enumerate(open(fp, errors="replace"), 1):
        section = numbered_h2_re.match(line)
        if section:
            number = section.group(1)
            if number in seen_sections:
                err(
                    f"Duplicate numbered H2 in {rel}:{i}: "
                    f"section {number} first appears at line {seen_sections[number]}"
                )
            else:
                seen_sections[number] = i
        if unresolved_marker_re.search(line):
            err(f"Unresolved marker in {rel}:{i}: {line.strip()[:100]}")

# Canonical requirement IDs are defined only in subsystem REQUIREMENTS files.
requirement_re = re.compile(r"\bREQ-[A-Z]+-\d+\b")
requirement_row_re = re.compile(r"^\|\s*(REQ-[A-Z]+-\d+)\s*\|")
defined_requirements = set()
subsystems_dir = os.path.join(BASE, "docs", "03-subsystems")
for subsystem in os.listdir(subsystems_dir):
    fp = os.path.join(subsystems_dir, subsystem, "REQUIREMENTS.md")
    if not os.path.isfile(fp):
        continue
    for line in open(fp, errors="replace"):
        match = requirement_row_re.match(line)
        if match:
            defined_requirements.add(match.group(1))

local_requirement_prefixes = {"DOM", "PROTO", "FUZZ"}
for fp in walk_files(DOCS_DIR, (".md", ".json")):
    if is_implementation_plan(fp) or "templates" in fp.split(os.sep):
        continue
    rel = os.path.relpath(fp, BASE)
    for i, line in enumerate(open(fp, errors="replace"), 1):
        for requirement in requirement_re.findall(line):
            prefix = requirement.split("-", 2)[1]
            if (
                requirement not in defined_requirements
                and prefix not in local_requirement_prefixes
            ):
                err(f"Unknown requirement ID in {rel}:{i}: {requirement}")

# ── 3. Empty files ───────────────────────────────────────────────────

for fp in walk_files(BASE):
    if os.path.basename(fp).startswith("."):
        continue
    if os.path.getsize(fp) == 0:
        err(f"Empty file: {os.path.relpath(fp, BASE)}")

# ── 4. Broken relative Markdown links ────────────────────────────────

link_re = re.compile(r'\[([^\]]*)\]\(([^)]*\.md[^)]*)\)')
for fp in walk_files(BASE, ".md"):
    content = open(fp, errors='replace').read()
    for m in link_re.finditer(content):
        target = m.group(2).split('#')[0]
        if not target or target.startswith(('http://', 'https://')):
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(fp), target))
        if not os.path.exists(resolved):
            err(f"Broken link in {os.path.relpath(fp, BASE)}: -> {target}")

# ── 5. Floating branch references (URL / ref / commit / upstream evidence ONLY) ──

# Patterns that are legitimate — NOT flagged:
#   - "Branch (snapshot): dev" / "not followed" — describes snapshot policy
#   - Table cells with "OpenCode API..." — domain terminology
#
# Patterns we DO flag — floating reference as evidence/source:
#   1. GitHub URLs with /dev, /main, /HEAD, /master paths
#   2. ref: dev, ref: main, commit: dev, commit: main
#   3. upstream/opencode/.../file.ts — any SHA reference pointing to non-baseline

# Check 1: URLs to OpenCode with floating branch
url_branch_re = re.compile(
    r'https?://github\.com/anomalyco/opencode/(?:tree|blob)/(dev|main|HEAD|master)/',
    re.IGNORECASE
)
# Check 2: ref/commit keywords with floating values
ref_branch_re = re.compile(
    r'\b(?:ref|commit|branch)\s*[:=]\s*(dev|main|HEAD|master)\b',
    re.IGNORECASE
)
# Check 3: upstream/opencode path references — make sure if SHA is present, it's our baseline
# (Skip lines that mention our BASELINE_SHA — those are fine)

for fp in walk_files(BASE, ".md"):
    if is_implementation_plan(fp):
        continue
    rel = os.path.relpath(fp, BASE)
    for i, line in enumerate(open(fp, errors='replace'), 1):
        # Check URL patterns
        m = url_branch_re.search(line)
        if m:
            err(f"Floating URL ref in {rel}:{i}: {line.strip()[:100]}")
        # Check ref/commit patterns — but skip lines that are clearly not evidence
        m = ref_branch_re.search(line)
        if m:
            # Allow: explanations about snapshot policy
            if any(kw in line.lower() for kw in ['snapshot', 'закреплён', 'pinned', 'not followed', 'не плавающ']):
                continue
            err(f"Floating ref/commit in {rel}:{i}: {line.strip()[:100]}")

# ── 6. Baseline SHA consistency ──────────────────────────────────────

sha_re = re.compile(r'[0-9a-f]{40}')
for fp in walk_files(BASE, (".md", ".json")):
    content = open(fp, errors='replace').read()
    for sha in sha_re.findall(content):
        if sha != BASELINE_SHA:
            # Allow sha-like strings that aren't actually git SHAs in context
            # (e.g. they appear in error messages, hex dumps, etc.)
            # We only flag if the surrounding context mentions OpenCode
            idx = content.find(sha)
            context = content[max(0,idx-80):idx+80].lower()
            if 'opencode' in context or 'upstream' in context or 'baseline' in context:
                warn(f"Non-baseline SHA near OpenCode context in {os.path.relpath(fp, BASE)}: {sha[:12]}")

# ── 7. No claims of implementation ───────────────────────────────────

impl_re = re.compile(r'\b(?:уже\s+реализован|already\s+implemented|is implemented|проходит тесты|passes tests)\b', re.IGNORECASE)
for fp in walk_files(BASE, ".md"):
    if is_implementation_plan(fp):
        continue
    rel = os.path.relpath(fp, BASE)
    for i, line in enumerate(open(fp, errors='replace'), 1):
        if impl_re.search(line):
            # Allow in ADRs/decisions that explicitly document decisions, not claims
            if 'adr' in rel.lower() or 'decision' in rel.lower():
                continue
            if 'not yet' in line.lower() or 'не реализован' in line.lower():
                continue
            warn(f"Possible implementation claim in {rel}:{i}: {line.strip()[:100]}")

# ── Summary ──────────────────────────────────────────────────────────

print(f"=== GOCODE Docs Validator ===")
print(f"Baseline: {BASELINE_SHA[:12]}")
print(f"Errors:   {len(errors)}")
print(f"Warnings: {len(warnings)}")

if errors:
    print(f"\n❌ ERRORS:")
    for e in errors:
        print(f"  • {e}")

if warnings:
    print(f"\n⚠️ WARNINGS:")
    for w in warnings:
        print(f"  • {w}")

if not errors and not warnings:
    print("\n✓ All checks passed.")
elif not errors:
    print("\n✓ No errors (warnings only).")

sys.exit(1 if errors or (strict and warnings) else 0)
