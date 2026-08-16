"""Resolve concrete frontend and browser targets without package-local PATH lookup."""

from __future__ import annotations

import json
import os
import platform
import stat
import sys
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError


def _frontend_platform() -> str:
    """Exact platform tag for gate host binaries (esbuild and browsers)."""
    tag = {
        ("darwin", "arm64"): "darwin-arm64",
        ("darwin", "x86_64"): "darwin-x64",
        ("linux", "x86_64"): "linux-x64",
    }.get((sys.platform, platform.machine()))
    if tag is None:
        raise LocalInputReceiptError("frontend platform is unsupported")
    return tag


def _esbuild_binary(root: Path, tag: str) -> Path:
    candidates = list(
        root.glob(
            f"node_modules/.pnpm/@esbuild+{tag}@*/node_modules/@esbuild/{tag}/bin/esbuild"
        )
    )
    if len(candidates) != 1:
        raise LocalInputReceiptError("esbuild platform package is unavailable or ambiguous")
    return candidates[0]


def _chromium_binary(browser_root: Path, revision: str, headless: bool) -> Path:
    if sys.platform == "darwin":
        tag = "mac-arm64" if platform.machine() == "arm64" else "mac-x64"
        if headless:
            return browser_root / (
                f"chromium_headless_shell-{revision}/"
                f"chrome-headless-shell-{tag}/chrome-headless-shell"
            )
        bundle_root = browser_root / f"chromium-{revision}/chrome-{tag}"
        executables = list(
            bundle_root.glob("*.app/Contents/MacOS/*")
        )
        if len(executables) != 1:
            raise LocalInputReceiptError("Chromium bundle executable is unavailable or ambiguous")
        return executables[0]
    if headless:
        return browser_root / (
            f"chromium_headless_shell-{revision}/"
            "chrome-headless-shell-linux64/chrome-headless-shell"
        )
    return browser_root / f"chromium-{revision}/chrome-linux64/chrome"


def frontend_targets(root: Path, home: Path) -> dict[str, Path]:
    tag = _frontend_platform()
    relative = {
        "eslint": "node_modules/eslint/bin/eslint.js",
        "vitest": "node_modules/vitest/vitest.mjs",
        "vue_tsc": "apps/desktop/node_modules/vue-tsc/bin/vue-tsc.js",
        "vite": "node_modules/vite/bin/vite.js",
        "playwright": "node_modules/@playwright/test/cli.js",
    }
    targets = {name: _load_target(root / path, root) for name, path in relative.items()}
    targets["esbuild"] = _load_target(_esbuild_binary(root, tag), root)
    revision = _chromium_revision(root)
    browser_root = home / ".cache/ms-playwright"
    targets["playwright_chromium"] = _load_target(
        _chromium_binary(browser_root, revision, headless=False), browser_root
    )
    targets["playwright_headless_shell"] = _load_target(
        _chromium_binary(browser_root, revision, headless=True), browser_root
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
