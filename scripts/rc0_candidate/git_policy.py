"""Forbidden local Git controls for fixture inspection."""

from __future__ import annotations


class GitInspectionError(ValueError):
    def __init__(self, reason: str, diagnostic: str):
        super().__init__(diagnostic)
        self.reason = reason
        self.diagnostic = diagnostic


def unsafe_config(entries: tuple[tuple[str, str], ...]) -> bool:
    for key, _value in entries:
        if key.startswith(("alias.", "include.", "includeif.", "credential.", "url.")):
            return True
        if key in (
            "http.proxy", "https.proxy", "http.extraheader", "core.hookspath",
            "core.fsmonitor", "core.sshcommand", "core.excludesfile",
            "core.alternaterefscommand", "extensions.worktreeconfig",
        ):
            return True
        if key.startswith(("http.", "https.")) and key.endswith((".proxy", ".extraheader")):
            return True
        if key.startswith("remote.") and key.endswith((".promisor", ".partialclonefilter", ".proxy")):
            return True
        if key == "extensions.partialclone":
            return True
    return False
