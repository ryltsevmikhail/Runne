#!/usr/bin/env python3
"""Path-filtered scoped local CI: run only gates relevant to changed paths.

The canonical receipt gate stays `pnpm ci:local` (scripts/ci-local.sh).
This module selects a subset of the same gates from the git change set and
runs it inside the same execution namespace. Its report is informational
and is NOT a local-input receipt: it never claims skipped gates satisfied.

Gate ids match the sections guarded by `gate_enabled` in
scripts/ci-local-inputs.sh, plus the orchestrator-run gates below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_namespace import execution_namespace
from scripts.ci_local_receipt_runtime import resolve_trusted_runtime
from scripts.ci_local_scope_classify import (
    ALL_GATES,
    ARCHITECTURE,
    DOCS,
    classify,
    select_gates,
)

SCHEMA = "gocode.local-inputs-scoped/1"

INPUT_SCRIPT = "scripts/ci-local-inputs.sh"
MAX_CHANGED_FILES = 200
MAX_DISPLAYED_FILES = 50


def _git(root: Path, git: Path, *arguments: str) -> str:
    completed = subprocess.run(
        (os.fspath(git), *arguments), cwd=root,
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        raise LocalInputReceiptError(f"git command failed: {arguments[0]}")
    return completed.stdout


def changed_files(root: Path, git: Path, base: str | None) -> list[str]:
    """Union of committed changes since base and uncommitted worktree changes."""
    files: set[str] = set()
    if base is not None:
        try:
            diff = _git(root, git, "diff", "--name-only", "-z", f"{base}...HEAD")
        except LocalInputReceiptError as error:
            raise LocalInputReceiptError(f"base revision is unavailable: {base}") from error
        files.update(path for path in diff.split("\0") if path)
    for record in _git(root, git, "status", "--porcelain=v1", "-z").split("\0"):
        if not record or record[2:3] != " ":
            continue  # rename/copy old-path records carry no status prefix
        files.add(record[3:])
    return sorted(files)


def resolve_base(root: Path, git: Path, explicit: str | None) -> str | None:
    """--base wins, then GOCODE_CI_BASE, then divergence from origin/main."""
    if explicit:
        return explicit
    environment_base = os.environ.get("GOCODE_CI_BASE")
    if environment_base:
        return environment_base
    try:
        head = _git(root, git, "rev-parse", "HEAD").strip()
        upstream = _git(
            root, git, "rev-parse", "--verify", "--quiet", "origin/main"
        ).strip()
        merge_base = _git(root, git, "merge-base", "origin/main", "HEAD").strip()
    except LocalInputReceiptError:
        return None
    if not upstream or merge_base == head:
        return None  # only uncommitted worktree changes
    return "origin/main"


def _system_git(root: Path) -> Path:
    for directory in ("/usr/bin", "/bin"):
        candidate = Path(directory) / "git"
        if candidate.exists():
            return candidate
    raise LocalInputReceiptError("system git is unavailable")


def _sha256_lines(lines: Sequence[str]) -> str:
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _report_path(requested: Path | None) -> Path:
    if requested is not None:
        requested.parent.mkdir(parents=True, exist_ok=True)
        return requested
    environment = os.environ.get("RUNNE_SCOPED_CI_REPORT")
    if environment:
        return Path(environment)
    descriptor, name = tempfile.mkstemp(
        prefix="gocode-scoped-ci-", suffix=".json",
        dir=os.environ.get("TMPDIR", "/tmp"),
    )
    os.close(descriptor)
    os.unlink(name)
    return Path(name)


def write_report(path: Path, record: dict) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)


def plan(root: Path, git: Path, base: str | None) -> tuple[list[str], set[str], list[str]]:
    """(changed_files, scopes, gates). Any failure falls back to full scope."""
    try:
        files = changed_files(root, git, base)
    except LocalInputReceiptError:
        return [], {"full"}, list(ALL_GATES)
    if not files:
        return [], set(), []
    if len(files) > MAX_CHANGED_FILES:
        return files, {"full"}, list(ALL_GATES)
    scopes: set[str] = set()
    for path in files:
        scopes.update(classify(path))
    return files, scopes, select_gates(scopes)


def _display(
    files: Sequence[str], scopes: Sequence[str], gates: Sequence[str],
    *, forced: bool = False,
) -> None:
    print("=== Scoped CI plan ===")
    print(f"  changed files ({len(files)}):")
    for path in files[:MAX_DISPLAYED_FILES]:
        print(f"    {path}")
    if len(files) > MAX_DISPLAYED_FILES:
        print(f"    ... and {len(files) - MAX_DISPLAYED_FILES} more")
    if not forced:
        print(f"  scopes: {', '.join(sorted(scopes)) if scopes else '(none)'}")
    print(f"  gates: {', '.join(gates) if gates else '(none)'}")
    if not gates and not forced:
        print("  no changes detected; nothing to check (run `pnpm ci:local` for the full gate)")
    elif not forced:
        skipped = [gate for gate in ALL_GATES if gate not in gates]
        print(f"  skipped: {', '.join(skipped) if skipped else '(none)'}")


def run_selected(root: Path, gates: Sequence[str]) -> tuple[int, dict[str, str]]:
    """Run the selected gates inside the canonical execution namespace."""
    runtime = resolve_trusted_runtime(root)
    results: dict[str, str] = {}
    with execution_namespace(runtime) as namespace:
        environment = dict(namespace.environment)
        environment["RUNNE_SCOPED_CI_GATES"] = " ".join(
            gate for gate in gates if gate in ALL_GATES
        )
        inputs = subprocess.run(
            (namespace.bash, root / INPUT_SCRIPT), cwd=root,
            env=environment, check=False,
        )
        status = "PASS" if inputs.returncode == 0 else "FAILED"
        for gate in (gate for gate in gates if gate in ALL_GATES):
            results[gate] = status
        python = environment["GOCODE_TRUSTED_PYTHON"]
        bash = environment["GOCODE_TRUSTED_BASH"]
        if DOCS in gates:
            docs = subprocess.run(
                (bash, root / "scripts/ci-local-docs.sh"), cwd=root,
                env=environment, check=False,
            )
            results[DOCS] = "PASS" if docs.returncode == 0 else "FAILED"
        if ARCHITECTURE in gates:
            architecture = subprocess.run(
                (python, root / "scripts/desktop/validate_architecture.py"),
                cwd=root, env=environment, check=False,
            )
            results[ARCHITECTURE] = (
                "PASS" if architecture.returncode == 0 else "FAILED"
            )
    for gate, result in results.items():
        print(f"  {gate}: {result}")
    return (1 if any(result != "PASS" for result in results.values()) else 0), results


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ci-local-scoped",
        description="Run only the local gates relevant to changed paths.",
    )
    parser.add_argument("--base", metavar="REF", default=None,
                        help="git revision to diff against (default: origin/main divergence or worktree)")
    parser.add_argument("--gates", metavar="LIST", default=None,
                        help="comma-separated gate ids to force (e.g. local-structural,docs)")
    parser.add_argument("--full", action="store_true",
                        help="run every gate (the canonical receipt gate stays `pnpm ci:local`)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan without executing gates")
    parser.add_argument("--report", metavar="PATH", default=None,
                        help="write the scoped CI report to PATH")
    try:
        args = parser.parse_args(arguments)
    except SystemExit as error:
        return int(error.code) if error.code is not None else 2
    root = Path.cwd().resolve(strict=True)
    git = _system_git(root)
    base = resolve_base(root, git, args.base)
    forced: Sequence[str] | None = None
    if args.gates:
        forced = tuple(gate.strip() for gate in args.gates.split(",") if gate.strip())
        unknown = [gate for gate in forced if gate not in ALL_GATES + (ARCHITECTURE,)]
        if unknown:
            print(f"ERROR: unknown gate ids: {', '.join(unknown)}", file=sys.stderr)
            return 2
    try:
        files = changed_files(root, git, base)
    except LocalInputReceiptError:
        files = []
    if forced is not None:
        gates = list(forced)
        scopes: set[str] = set()
    elif args.full:
        gates = list(ALL_GATES)
        scopes = {"full"}
    else:
        files, scopes, gates = plan(root, git, base)
    _display(files, scopes, gates, forced=forced is not None)
    sys.stdout.flush()
    if not gates or args.dry_run:
        return 0
    report = _report_path(Path(args.report) if args.report else None)
    exit_status, results = run_selected(root, gates)
    try:
        head = _git(root, git, "rev-parse", "HEAD").strip()
    except LocalInputReceiptError:
        head = ""
    record = {
        "schema": SCHEMA,
        "issued_at_unix": int(time.time()),
        "base_revision": base or "",
        "head_revision": head,
        "changed_files": files,
        "changed_files_sha256": _sha256_lines(files),
        "scopes": sorted(scopes),
        "gates": gates,
        "results": results,
        "exit_status": exit_status,
    }
    write_report(report, record)
    print(f"=== Scoped CI: {'FAILED' if exit_status else 'PASSED'} ===")
    print(f"Scoped CI report: {report}")
    return exit_status


if __name__ == "__main__":
    raise SystemExit(main())
