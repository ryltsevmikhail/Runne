"""Path classification and gate selection for the scoped local CI.

Separated from the orchestrator so the classification table stays small,
testable, and under the 300-line source limit.

Scope vocabulary and gate ids are shared with scripts/ci-local-inputs.sh
(sections guarded by `gate_enabled`).
"""

from __future__ import annotations

from typing import Sequence

STRUCTURAL = "local-structural"
CONTAINMENT = "containment"
RUNTIME_PINNED = "runtime-pinned"
RUNTIME_MSRV = "runtime-msrv"
FRONTEND = "frontend"
DOCS = "docs"
ARCHITECTURE = "architecture"

ALL_GATES = (
    STRUCTURAL, CONTAINMENT, RUNTIME_PINNED, RUNTIME_MSRV, FRONTEND, DOCS,
)

_RUNTIME_PREFIXES = (
    "crates/", "ci/runtime/",
    "docs/profiles/", "docs/schemas/opencode-baseline-inventory-",
)
_FRONTEND_PREFIXES = (
    "apps/", "packages/", "contracts/", "tests/desktop/", "scripts/desktop/",
)
_FULL_PREFIXES = ("upstream/", ".github/", "ci/", "tests/")
_RUNTIME_FILES = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain",
    "scripts/ci.sh", "scripts/check-deps.py", "scripts/check-source-file-length.py",
}
_FRONTEND_FILES = {
    "playwright.config.ts", "pnpm-workspace.yaml", "package.json",
    "pnpm-lock.yaml", "eslint.config.mjs", "tsconfig.base.json",
}
_DOCS_FILES = {
    "AGENTS.md", "README.md", "CONTRIBUTING.md",

}


def classify(path: str) -> set[str]:
    """Map a repository-relative path to its scopes.

    Unclassified or unexpected paths resolve to {"full"}: a conservative
    fallback that selects every gate rather than risking a missed one.
    """
    scopes: set[str] = set()
    if path.startswith(_RUNTIME_PREFIXES) or path in _RUNTIME_FILES \
            or path.startswith("scripts/verify-"):
        scopes.add("runtime")
    if path.startswith(_FRONTEND_PREFIXES) or path in _FRONTEND_FILES:
        scopes.add("frontend")
    if path.startswith("docs/") or path in _DOCS_FILES:
        scopes.add("docs")
    if scopes:
        return scopes
    return {"full"} if path.startswith(_FULL_PREFIXES) else {"full"}


def select_gates(scopes: Sequence[str]) -> list[str]:
    """Ordered gate list for the computed scopes; "full" selects everything."""
    selected = set(scopes)
    known = {"runtime", "frontend", "docs"}
    if "full" in selected or not selected.issubset(known):
        return list(ALL_GATES)  # unexpected scope: run everything, fail safe
    gates: list[str] = [STRUCTURAL]
    if "runtime" in selected:
        gates.extend((CONTAINMENT, RUNTIME_PINNED, RUNTIME_MSRV))
    if "frontend" in selected:
        gates.append(FRONTEND)
    if "docs" in selected:
        gates.append(DOCS)
    if "runtime" in selected and "frontend" not in selected:
        # The frontend closure already runs validate_architecture.py twice;
        # run it here so a runtime-only change still checks the boundary.
        gates.append(ARCHITECTURE)
    return gates
