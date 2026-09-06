"""Alias-safe scan derived from the qualification admission allowlist."""
from __future__ import annotations

NATIVE_QUALIFICATION_NON_DELIVERY_OWNERS = {
    NATIVE_QUALIFICATION_ADMISSION_SOURCE,
    Path("apps/desktop/src-tauri/src/bundled_runtime.rs"),
    Path("apps/desktop/src-tauri/src/lib_parts/run.rs"),
}
NATIVE_QUALIFICATION_TEST_ONLY_PATHS = frozenset({
    Path("apps/desktop/src-tauri/src/qualification_ticket_tests.rs"),
    Path("crates/runne-platform-desktop/src/protected_runtime/qualification_relay_tests.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/tests.rs"),
    Path("crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/connected_tests.rs"),
})
if not NATIVE_QUALIFICATION_TEST_ONLY_PATHS <= NATIVE_QUALIFICATION_ADMISSION_ALLOWED:
    raise RuntimeError("native qualification test-only path is absent from the admission allowlist")
NATIVE_QUALIFICATION_FORBIDDEN_IMPORT_ROOTS = {"rusqlite", "sqlite3", "reqwest"}
NATIVE_QUALIFICATION_FORBIDDEN_STD_BRANCHES = {"env", "fs", "path"}


def _native_qualification_delivery_path(relative: Path) -> bool:
    return (
        relative in NATIVE_QUALIFICATION_ADMISSION_ALLOWED
        and relative not in NATIVE_QUALIFICATION_NON_DELIVERY_OWNERS
        and relative not in NATIVE_QUALIFICATION_TEST_ONLY_PATHS
    )


def _split_rust_use_tree(tree: str) -> list[str]:
    items, start, depth = [], 0, 0
    for index, character in enumerate(tree):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        elif character == "," and depth == 0:
            items.append(tree[start:index])
            start = index + 1
    items.append(tree[start:])
    return items


def _forbidden_std_use(body: str) -> bool:
    body = body.strip()
    if body.startswith("::"):
        body = body[2:].lstrip()
    if re.match(r"std\s+as\b", body) or body == "std":
        return True
    match = re.match(r"std\s*::\s*(.*)", body, re.DOTALL)
    if match is None:
        return False
    tree = match.group(1).strip()
    if tree.startswith("{") and tree.endswith("}"):
        heads = (
            re.match(r"\s*([A-Za-z_]\w*)", item)
            for item in _split_rust_use_tree(tree[1:-1])
        )
        return any(
            head is not None
            and (
                head.group(1) in NATIVE_QUALIFICATION_FORBIDDEN_STD_BRANCHES
                or (head.group(1) == "self" and re.search(r"\bas\b", head.string))
            )
            for head in heads
        )
    head = re.match(r"([A-Za-z_]\w*)", tree)
    return head is not None and head.group(1) in NATIVE_QUALIFICATION_FORBIDDEN_STD_BRANCHES


def _forbidden_use_tree(tree: str) -> bool:
    tree = tree.strip()
    if tree.startswith("{") and tree.endswith("}"):
        return any(_forbidden_use_tree(item) for item in _split_rust_use_tree(tree[1:-1]))
    root = tree[2:].lstrip() if tree.startswith("::") else tree
    root_match = re.match(r"([A-Za-z_]\w*)", root)
    return (
        root_match is not None
        and root_match.group(1) in NATIVE_QUALIFICATION_FORBIDDEN_IMPORT_ROOTS
    ) or _forbidden_std_use(tree)


def _forbidden_delivery_import(source: str) -> bool:
    for statement in re.finditer(r"(?ms)\buse\s+(?P<body>[^;]+);", source):
        if _forbidden_use_tree(statement.group("body")):
            return True
    return re.search(
        r"(?m)\bextern\s+crate\s+(?:::)?(?:std|rusqlite|sqlite3|reqwest)\b",
        source,
    ) is not None


def native_qualification_delivery_forbidden(relative: Path, source: str) -> bool:
    if not _native_qualification_delivery_path(relative):
        return False
    masked = _mask_rust_comments_and_strings(source)
    normalized = re.sub(r"\br#(?=[A-Za-z_])", "", masked)
    return (
        _forbidden_delivery_import(normalized)
        or NATIVE_QUALIFICATION_DELIVERY_FORBIDDEN.search(normalized) is not None
    )
