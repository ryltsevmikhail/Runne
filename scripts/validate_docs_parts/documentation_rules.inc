"""Documentation structure, reference, and summary validation phase."""

# Task 2 intentionally leaves the three canonical manifests absent.  Once
# Task 10a commits all of them, closed-world validation becomes mandatory.
if all(os.path.isfile(path) for path in DOCS_TAXONOMY_MANIFESTS):
    for diagnostic in validate_document_universe(Path(BASE)):
        err(f"Documentation taxonomy: {diagnostic}")

for file_path in walk_files(DOCS_DIR, ".md"):
    if is_implementation_plan(file_path):
        continue
    with open(file_path, encoding="utf-8") as document:
        head = document.read(200)
    if not head.startswith("---"):
        err(f"Missing front matter: {os.path.relpath(file_path, BASE)}")

numbered_h2_re = re.compile(r"^##\s+(\d+)\.")
unresolved_marker_re = re.compile(r"\{SHA\}|\bTBD\b", re.IGNORECASE)
for file_path in walk_files(DOCS_DIR, ".md"):
    if is_implementation_plan(file_path) or "templates" in file_path.split(os.sep):
        continue
    relative = os.path.relpath(file_path, BASE)
    seen_sections = {}
    for line_number, line in enumerate(open(file_path, encoding="utf-8", errors="replace"), 1):
        section = numbered_h2_re.match(line)
        if section:
            number = section.group(1)
            if number in seen_sections:
                err(f"Duplicate numbered H2 in {relative}:{line_number}: section {number} first appears at line {seen_sections[number]}")
            else:
                seen_sections[number] = line_number
        if unresolved_marker_re.search(line):
            err(f"Unresolved marker in {relative}:{line_number}: {line.strip()[:100]}")

requirement_re = re.compile(r"\bREQ-[A-Z]+-\d+\b")
requirement_row_re = re.compile(r"^\|\s*(REQ-[A-Z]+-\d+)\s*\|")
defined_requirements = set()
subsystems_dir = os.path.join(BASE, "docs", "03-subsystems")
for subsystem in os.listdir(subsystems_dir):
    requirement_path = os.path.join(subsystems_dir, subsystem, "REQUIREMENTS.md")
    if not os.path.isfile(requirement_path):
        continue
    for line in open(requirement_path, encoding="utf-8", errors="replace"):
        match = requirement_row_re.match(line)
        if match:
            defined_requirements.add(match.group(1))

subsystem_dirs = sum(
    os.path.isfile(os.path.join(subsystems_dir, name, "REQUIREMENTS.md"))
    for name in os.listdir(subsystems_dir)
)
subsystem_docs = list(walk_files(subsystems_dir, ".md"))
ready_subsystem_docs = sum(
    re.search(r"(?m)^status:\s*[\"']?ready[\"']?\s*$", open(path, encoding="utf-8").read(300))
    is not None
    for path in subsystem_docs
)
adr_count = sum(
    re.fullmatch(r"ADR-(?!0000)\d{4}-.*\.md", name) is not None
    for name in os.listdir(os.path.join(DOCS_DIR, "adr"))
)
inventory_text = open(os.path.join(subsystems_dir, "README.md"), encoding="utf-8").read()
for label, value in (("Subsystems", subsystem_dirs), ("Total ready", ready_subsystem_docs), ("Canonical REQ coverage", len(defined_requirements))):
    if not re.search(rf"\*\*{re.escape(label)}:\*\*\s*{value}(?:/{value})?\b", inventory_text):
        err(f"Stale subsystem inventory for {label}: expected {value}")
if f"ADR-0001…ADR-{adr_count:04d}" not in open(os.path.join(DOCS_DIR, "README.md"), encoding="utf-8").read():
    err(f"Stale ADR range in docs/README.md: expected ADR-{adr_count:04d}")

local_requirement_prefixes = {"DOM", "PROTO", "FUZZ"}
for file_path in walk_files(DOCS_DIR, (".md", ".json")):
    if is_implementation_plan(file_path) or "templates" in file_path.split(os.sep):
        continue
    relative = os.path.relpath(file_path, BASE)
    for line_number, line in enumerate(open(file_path, encoding="utf-8", errors="replace"), 1):
        for requirement in requirement_re.findall(line):
            prefix = requirement.split("-", 2)[1]
            if requirement not in defined_requirements and prefix not in local_requirement_prefixes:
                err(f"Unknown requirement ID in {relative}:{line_number}: {requirement}")

for file_path in walk_files(BASE):
    if not os.path.basename(file_path).startswith(".") and os.path.getsize(file_path) == 0:
        err(f"Empty file: {os.path.relpath(file_path, BASE)}")

link_re = re.compile(r'\[([^\]]*)\]\(([^)]*\.md[^)]*)\)')
for file_path in walk_files(BASE, ".md"):
    with open(file_path, encoding="utf-8", errors="replace") as document:
        content = document.read()
    for match in link_re.finditer(content):
        target = match.group(2).split("#")[0]
        if not target or target.startswith(("http://", "https://")):
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(file_path), target))
        if not os.path.exists(resolved):
            err(f"Broken link in {os.path.relpath(file_path, BASE)}: -> {target}")

url_branch_re = re.compile(r"https?://github\.com/anomalyco/opencode/(?:tree|blob)/(dev|main|HEAD|master)/", re.IGNORECASE)
ref_branch_re = re.compile(r"\b(?:ref|commit|branch)\s*[:=]\s*(dev|main|HEAD|master)\b", re.IGNORECASE)
for file_path in walk_files(BASE, ".md"):
    if is_implementation_plan(file_path):
        continue
    relative = os.path.relpath(file_path, BASE)
    for line_number, line in enumerate(open(file_path, encoding="utf-8", errors="replace"), 1):
        if url_branch_re.search(line):
            err(f"Floating URL ref in {relative}:{line_number}: {line.strip()[:100]}")
        if ref_branch_re.search(line):
            if any(keyword in line.lower() for keyword in ["snapshot", "закреплён", "pinned", "not followed", "не плавающ"]):
                continue
            err(f"Floating ref/commit in {relative}:{line_number}: {line.strip()[:100]}")

sha_re = re.compile(r"[0-9a-f]{40}")
for file_path in walk_files(BASE, (".md", ".json")):
    with open(file_path, encoding="utf-8", errors="replace") as document:
        content = document.read()
    for sha in sha_re.findall(content):
        if sha == BASELINE_SHA:
            continue
        position = content.find(sha)
        context = content[max(0, position - 80):position + 80].lower()
        if "opencode" in context or "upstream" in context or "baseline" in context:
            warn(f"Non-baseline SHA near OpenCode context in {os.path.relpath(file_path, BASE)}: {sha[:12]}")

impl_re = re.compile(r"\b(?:уже\s+реализован|already\s+implemented|is implemented|проходит тесты|passes tests)\b", re.IGNORECASE)
for file_path in walk_files(BASE, ".md"):
    if is_implementation_plan(file_path):
        continue
    relative = os.path.relpath(file_path, BASE)
    for line_number, line in enumerate(open(file_path, encoding="utf-8", errors="replace"), 1):
        if impl_re.search(line):
            if "adr" in relative.lower() or "decision" in relative.lower():
                continue
            if "not yet" in line.lower() or "не реализован" in line.lower():
                continue
            warn(f"Possible implementation claim in {relative}:{line_number}: {line.strip()[:100]}")

print("=== GOCODE Docs Validator ===")
print(f"Baseline: {BASELINE_SHA[:12]}")
print(f"Errors:   {len(errors)}")
print(f"Warnings: {len(warnings)}")
if errors:
    print("\n❌ ERRORS:")
    for error in errors:
        print(f"  • {error}")
if warnings:
    print("\n⚠️ WARNINGS:")
    for warning in warnings:
        print(f"  • {warning}")
if not errors and not warnings:
    print("\n✓ All checks passed.")
elif not errors:
    print("\n✓ No errors (warnings only).")
sys.exit(1 if errors or (strict and warnings) else 0)
