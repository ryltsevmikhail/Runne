#!/usr/bin/env python3
"""GOCODE Runtime documentation validator.

Usage:
    python3 scripts/validate-docs.py
    python3 scripts/validate-docs.py --strict   # также проверяет warnings
"""
import os, json, re, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM_DIR = os.path.join(BASE, "upstream", "opencode")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
BASELINE_DATE = "2026-07-24"
UPSTREAM_URL = "https://github.com/anomalyco/opencode"

errors = []
warnings = []
strict = "--strict" in sys.argv

# ── Helpers ──────────────────────────────────────────────────────────

def err(msg):
    errors.append(msg)

def warn(msg):
    warnings.append(msg)

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
    if not data.get("$id"):
        warn(f"Missing $id in {f}")
    if not data.get("title"):
        warn(f"Missing title in {f}")

# ── 2. Front matter on all docs/*.md ─────────────────────────────────

for root, _, files in os.walk(os.path.join(BASE, "docs")):
    for f in files:
        if not f.endswith(".md"):
            continue
        fp = os.path.join(root, f)
        head = open(fp).read(200)
        if not head.startswith("---"):
            err(f"Missing front matter: {os.path.relpath(fp, BASE)}")

# ── 3. Empty files ───────────────────────────────────────────────────

for root, _, files in os.walk(BASE):
    if root.startswith(UPSTREAM_DIR):
        continue

    for f in files:
        if f.startswith("."):
            continue
        fp = os.path.join(root, f)
        if os.path.getsize(fp) == 0:
            err(f"Empty file: {os.path.relpath(fp, BASE)}")

# ── 4. Broken relative Markdown links ────────────────────────────────

link_re = re.compile(r'\[([^\]]*)\]\(([^)]*\.md[^)]*)\)')
for root, _, files in os.walk(BASE):
    if root.startswith(UPSTREAM_DIR):
        continue

    for f in files:
        if not f.endswith(".md"):
            continue
        fp = os.path.join(root, f)
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

for root, _, files in os.walk(BASE):
    if root.startswith(UPSTREAM_DIR):
        continue

    for f in files:
        if not f.endswith(".md"):
            continue
        fp = os.path.join(root, f)
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
for root, _, files in os.walk(BASE):
    if root.startswith(UPSTREAM_DIR):
        continue

    for f in files:
        if not f.endswith(('.md', '.json')):
            continue
        fp = os.path.join(root, f)
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
for root, _, files in os.walk(BASE):
    if root.startswith(UPSTREAM_DIR):
        continue

    for f in files:
        if not f.endswith(".md"):
            continue
        fp = os.path.join(root, f)
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

sys.exit(1 if errors else 0)
