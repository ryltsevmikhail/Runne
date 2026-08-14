"""Strict local I/O and Git source identity helpers."""

import hashlib
import json
import os
import subprocess
from pathlib import Path


def load_json(path: Path) -> object:
    """Read JSON and reject duplicate object keys at every nesting level."""

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def has_raw_sha256(raw: bytes, sidecar: str) -> bool:
    """Match the repository's exact raw-byte SHA-256 sidecar convention."""

    return sidecar == f"sha256:{hashlib.sha256(raw).hexdigest()}\n"


def registry_ids(path: Path, prefix: str) -> set[str]:
    """Extract canonical table IDs without treating arbitrary prose as an ID registry."""

    return {
        line.split("|", 2)[1].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("| ") and line.split("|", 2)[1].strip().startswith(prefix)
    }


def git_output(root: Path, *args: str) -> bytes:
    return subprocess.run(("git", "-C", str(root), *args), check=True, capture_output=True).stdout


def clean_source_paths(root: Path) -> bool:
    """Evidence-only changes cannot alter the candidate source identity."""

    changed = git_output(root, "diff", "--name-only", "-z", "HEAD").split(b"\0")
    untracked = git_output(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    paths = [item.decode("utf-8", "surrogateescape") for item in (*changed, *untracked) if item]
    return all(path.startswith("docs/evidence/") for path in paths)


def resolve_commit(root: Path, source_ref: str) -> str:
    return git_output(root, "rev-parse", "--verify", f"{source_ref}^{{commit}}").decode("ascii").strip()


def evidence_only_difference(root: Path, left: str, right: str) -> bool:
    paths = git_output(root, "diff", "--name-only", "-z", left, right).split(b"\0")
    return all(path.startswith(b"docs/evidence/") for path in paths if path)


def canonical_source_content_digest(root: Path, source_ref: str) -> str:
    """Hash sorted Git blobs, excluding only immutable evidence records."""

    entries = git_output(root, "ls-tree", "-r", "-z", source_ref).split(b"\0")
    digest = hashlib.sha256()
    for entry in entries:
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split(b" ", 2)
        if path.startswith(b"docs/evidence/"):
            continue
        if kind == b"blob":
            content = git_output(root, "show", f"{source_ref}:{path.decode('utf-8', 'surrogateescape')}")
        elif kind == b"commit" and mode == b"160000":
            content = object_id
        else:
            raise ValueError(f"unsupported Git tree entry: {mode!r} {kind!r}")
        content_digest = hashlib.sha256(content).digest()
        digest.update(len(path).to_bytes(8, "big"))
        digest.update(path)
        digest.update(len(mode).to_bytes(2, "big"))
        digest.update(mode)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content_digest)
    return digest.hexdigest()


def protected_policy() -> dict[str, str] | None:
    """Read only protected GitHub Actions inputs; local configuration is untrusted."""

    names = {
        "repository": "GOCODE_DESKTOP_ATTEST_REPOSITORY",
        "signer_workflow": "GOCODE_DESKTOP_ATTEST_SIGNER_WORKFLOW",
        "source_ref": "GOCODE_DESKTOP_ATTEST_SOURCE_REF",
    }
    values = {key: os.environ.get(name, "") for key, name in names.items()}
    if os.environ.get("GITHUB_ACTIONS") != "true" or not all(values.values()):
        return None
    return values


def verify_attestation(subject: Path, bundle: Path, policy: dict[str, str], source_commit: str) -> dict[str, object] | None:
    """Verify one Sigstore attestation with the fixed GitHub CLI contract."""

    command = ["gh", "attestation", "verify", str(subject), "--bundle", str(bundle), "--repo", policy["repository"], "--signer-workflow", policy["signer_workflow"], "--source-ref", policy["source_ref"], "--source-digest", source_commit, "--predicate-type", "https://slsa.dev/provenance/v1", "--no-public-good", "--format", "json"]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            return None
        value = json.loads(result.stdout)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict) or not isinstance(value[0].get("attestation"), dict):
        return None
    verified = value[0].get("verificationResult")
    if not isinstance(verified, dict):
        return None
    statement = verified.get("statement")
    if not isinstance(statement, dict) or not isinstance(statement.get("subject"), list) or len(statement["subject"]) != 1 or not isinstance(statement.get("predicate"), dict):
        return None
    subject_row = statement["subject"][0]
    digest = subject_row.get("digest") if isinstance(subject_row, dict) else None
    if not isinstance(digest, dict) or set(digest) != {"sha256"} or digest["sha256"] != sha256_file(subject):
        return None
    return statement["predicate"]
