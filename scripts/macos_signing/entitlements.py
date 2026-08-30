import plistlib
import stat
from pathlib import Path
from typing import Sequence

from .hashing import sha256_bytes
from .models import EntitlementBinding


def bind_entitlements(paths: Sequence[Path]) -> tuple[EntitlementBinding, ...]:
    return bind_entitlements_exact(paths, ({},) * len(paths))


def bind_entitlements_exact(
    paths: Sequence[Path],
    expected_payloads: Sequence[dict],
) -> tuple[EntitlementBinding, ...]:
    if len(paths) != len(expected_payloads):
        raise ValueError("entitlement policy length mismatch")
    bindings = tuple(
        _binding(path, expected)
        for path, expected in zip(paths, expected_payloads, strict=True)
    )
    identities = {(binding.device, binding.inode) for binding in bindings}
    if len(identities) != len(bindings):
        raise ValueError("entitlements must use distinct files")
    return bindings


def entitlement_binding_is_current(binding: EntitlementBinding) -> bool:
    try:
        return _binding(binding.canonical_path, None) == binding
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def _binding(path: Path, expected_payload: dict | None) -> EntitlementBinding:
    if not isinstance(path, Path) or path.is_symlink():
        raise ValueError("invalid entitlement path")
    canonical = path.resolve(strict=True)
    information = canonical.lstat()
    if canonical.is_symlink() or not stat.S_ISREG(information.st_mode):
        raise ValueError("invalid entitlement file")
    value = canonical.read_bytes()
    payload = plistlib.loads(value)
    if type(payload) is not dict or (
        expected_payload is not None and payload != expected_payload
    ):
        raise ValueError("invalid entitlement plist")
    return EntitlementBinding(
        canonical,
        sha256_bytes(value),
        information.st_dev,
        information.st_ino,
    )
