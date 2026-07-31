#!/usr/bin/env python3
"""GOCODE Runtime documentation validator.

Usage:
    python3 scripts/validate-docs.py
    python3 scripts/validate-docs.py --strict   # также проверяет warnings
"""
import hashlib, os, json, re, sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM_DIR = os.path.join(BASE, "upstream", "opencode")
DOCS_DIR = os.path.join(BASE, "docs")
IMPLEMENTATION_PLANS_DIR = os.path.join(DOCS_DIR, "superpowers", "plans")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
BASELINE_DATE = "2026-07-24"
UPSTREAM_URL = "https://github.com/anomalyco/opencode"
IGNORED_TREE_NAMES = {".git", ".worktrees", "node_modules", "target"}
EXCLUDED_ROOTS = {
    os.path.join(DOCS_DIR, "desktop"),
    os.path.join(BASE, "upstream", "desktop"),
}
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
            and os.path.join(current_root, directory) not in EXCLUDED_ROOTS
        ]
        for filename in files:
            if suffixes is None or filename.endswith(suffixes):
                yield os.path.join(current_root, filename)

def is_implementation_plan(path):
    return path.startswith(IMPLEMENTATION_PLANS_DIR + os.sep)

def validate_const_instance(instance, schema, location):
    """Validate the closed const-only subset used by immutable profiles."""
    if "const" in schema and instance != schema["const"]:
        err(f"{location}: value differs from schema const")
        return
    expected_type = schema.get("type")
    if expected_type == "null" and instance is not None:
        err(f"{location}: expected null")
        return
    if expected_type == "object":
        if not isinstance(instance, dict):
            err(f"{location}: expected object")
            return
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = sorted(set(required) - set(instance))
        if missing:
            err(f"{location}: missing required fields {missing}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(instance) - set(properties))
            if unknown:
                err(f"{location}: unknown fields {unknown}")
        for key in sorted(set(instance) & set(properties)):
            validate_const_instance(
                instance[key], properties[key], f"{location}.{key}"
            )

# ── 1. JSON Schema validity ──────────────────────────────────────────

schemas_dir = os.path.join(BASE, "docs", "schemas")
for f in sorted(os.listdir(schemas_dir)):
    if not f.endswith(".json"):
        continue
    fp = os.path.join(schemas_dir, f)
    try:
        with open(fp, encoding="utf-8") as schema_file:
            data = json.load(schema_file)
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

# ── 1a. Immutable OpenAI profile/golden integrity ───────────────────

openai_profile_path = os.path.join(
    DOCS_DIR, "profiles", "openai-responses-text-v1.json"
)
openai_digest_path = os.path.join(
    DOCS_DIR, "profiles", "openai-responses-text-v1.digest"
)
openai_schema_path = os.path.join(
    schemas_dir, "openai-responses-text-profile-v1.schema.json"
)
openai_golden_path = os.path.join(
    DOCS_DIR, "golden", "openai-responses-text-request-v1.json"
)
openai_paths = (
    openai_profile_path,
    openai_digest_path,
    openai_schema_path,
    openai_golden_path,
)
if all(os.path.isfile(path) for path in openai_paths):
    try:
        profile_bytes = open(openai_profile_path, "rb").read()
        profile = json.loads(profile_bytes)
        profile_schema = json.loads(open(openai_schema_path, encoding="utf-8").read())
        golden_bytes = open(openai_golden_path, "rb").read()
        golden = json.loads(golden_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        err(f"OpenAI immutable profile artifacts are unreadable: {error}")
    else:
        expected_digest = "sha256:" + hashlib.sha256(profile_bytes).hexdigest()
        actual_digest = open(openai_digest_path, encoding="utf-8").read().strip()
        if actual_digest != expected_digest:
            err("OpenAI profile digest sidecar mismatch")
        canonical_profile = (
            json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        if profile_bytes != canonical_profile:
            err("OpenAI profile bytes are not exact compact UTF-8 JSON plus LF")
        validate_const_instance(profile, profile_schema, "openai-profile")
        canonical_golden = (
            json.dumps(golden, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        if golden_bytes != canonical_golden:
            err("OpenAI request golden is not exact compact UTF-8 JSON plus LF")
        expected_golden_keys = {
            "model",
            "service_tier",
            "input",
            "max_output_tokens",
            "reasoning",
            "tools",
            "tool_choice",
            "background",
            "store",
            "stream",
        }
        if (
            not isinstance(golden, dict)
            or set(golden) != expected_golden_keys
            or golden.get("model") != profile.get("model", {}).get("request_id")
            or golden.get("service_tier")
            != profile.get("request", {}).get("service_tier")
            or not isinstance(golden.get("input"), list)
            or not golden.get("input")
            or golden.get("reasoning") != {"effort": "none"}
            or golden.get("tools") != []
            or golden.get("tool_choice") != "none"
            or golden.get("background") is not False
            or golden.get("store") is not False
            or golden.get("stream") is not True
        ):
            err("OpenAI request golden differs from the exact text-only profile")
        lowered_golden = golden_bytes.lower()
        for forbidden in (
            b"authorization",
            b"bearer",
            b"credential",
            b"api_key",
            b"secret_ref",
        ):
            if forbidden in lowered_golden:
                err(f"OpenAI request golden contains forbidden marker {forbidden!r}")
else:
    missing = [
        os.path.relpath(path, BASE)
        for path in openai_paths
        if not os.path.isfile(path)
    ]
    err(f"Missing immutable OpenAI profile artifacts: {missing}")

# ── 2. Front matter on all docs/*.md ─────────────────────────────────

for fp in walk_files(DOCS_DIR, ".md"):
    if is_implementation_plan(fp):
        continue
    with open(fp, encoding="utf-8") as doc_file:
        head = doc_file.read(200)
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
    for i, line in enumerate(open(fp, encoding="utf-8", errors="replace"), 1):
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
    for line in open(fp, encoding="utf-8", errors="replace"):
        match = requirement_row_re.match(line)
        if match:
            defined_requirements.add(match.group(1))

local_requirement_prefixes = {"DOM", "PROTO", "FUZZ"}
for fp in walk_files(DOCS_DIR, (".md", ".json")):
    if is_implementation_plan(fp) or "templates" in fp.split(os.sep):
        continue
    rel = os.path.relpath(fp, BASE)
    for i, line in enumerate(open(fp, encoding="utf-8", errors="replace"), 1):
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
    with open(fp, encoding="utf-8", errors="replace") as doc_file:
        content = doc_file.read()
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
    for i, line in enumerate(open(fp, encoding="utf-8", errors="replace"), 1):
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
    with open(fp, encoding="utf-8", errors="replace") as doc_file:
        content = doc_file.read()
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
    for i, line in enumerate(open(fp, encoding="utf-8", errors="replace"), 1):
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
