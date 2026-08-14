"""Resolve concrete frontend and browser targets without package-local PATH lookup."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError


def frontend_targets(root: Path, home: Path) -> dict[str, Path]:
    relative = {
        "eslint": "node_modules/eslint/bin/eslint.js",
        "vitest": "node_modules/vitest/vitest.mjs",
        "vue_tsc": "apps/desktop/node_modules/vue-tsc/bin/vue-tsc.js",
        "vite": "node_modules/vite/bin/vite.js",
        "playwright": "node_modules/@playwright/test/cli.js",
        "esbuild": "node_modules/.pnpm/@esbuild+linux-x64@0.28.1/node_modules/@esbuild/linux-x64/bin/esbuild",
    }
    targets = {name: _load_target(root / path, root) for name, path in relative.items()}
    revision = _chromium_revision(root)
    browser_root = home / ".cache/ms-playwright"
    targets["playwright_chromium"] = _load_target(
        browser_root / f"chromium-{revision}/chrome-linux64/chrome", browser_root
    )
    targets["playwright_headless_shell"] = _load_target(
        browser_root / f"chromium_headless_shell-{revision}/chrome-headless-shell-linux64/chrome-headless-shell",
        browser_root,
    )
    return targets


def _chromium_revision(root: Path) -> str:
    manifests = list(root.glob("node_modules/.pnpm/playwright-core@*/node_modules/playwright-core/browsers.json"))
    if len(manifests) != 1:
        raise LocalInputReceiptError("Playwright browser inventory is unavailable or ambiguous")
    try:
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        entries = manifest["browsers"]
        revisions = {
            entry["revision"] for entry in entries
            if entry.get("name") in {"chromium", "chromium-headless-shell"}
        }
    except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError) as error:
        raise LocalInputReceiptError("Playwright browser inventory is invalid") from error
    if len(revisions) != 1 or not next(iter(revisions)).isdigit():
        raise LocalInputReceiptError("Playwright Chromium revisions are inconsistent")
    return next(iter(revisions))


def _load_target(path: Path, boundary: Path) -> Path:
    try:
        canonical = path.resolve(strict=True)
        canonical.relative_to(boundary.resolve(strict=True))
        metadata = os.stat(canonical, follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise LocalInputReceiptError("frontend executable target is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022 or not metadata.st_mode & stat.S_IXUSR
    ):
        raise LocalInputReceiptError("frontend executable target is unsafe")
    return canonical
