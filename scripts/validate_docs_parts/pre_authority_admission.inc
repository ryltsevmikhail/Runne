"""Exact reviewed admission for temporary fixtures; never trust ambient state."""
import json
import os
import subprocess
import tempfile


TASK1_LITERAL_ALLOWLIST = frozenset((
    "docs/00-foundation/DOCUMENTATION_RULES.md", "docs/schemas/pre-authority-document-delta-v1.schema.json", "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json",
    "docs/adr/ADR-0027-v1-platform-scope.md", "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md", "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md", "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md",
    "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md",
    "scripts/validate_docs_impl.inc", "scripts/validate_docs_parts/documentation_rules.inc",
    "scripts/validate_docs_parts/pre_authority_admission.inc", "scripts/validate_docs_parts/pre_authority_claims.inc",
    "scripts/validate_docs_parts/pre_authority_document_delta.inc", "scripts/validate_docs_parts/pre_authority_snapshot.inc",
    "scripts/validate_docs_parts/pre_authority_legacy.inc",
    "scripts/tests/test_pre_authority_document_delta.py", "scripts/tests/test_pre_authority_document_delta_matrix.py",
    "scripts/tests/test_pre_authority_document_delta_phase_b.py", "scripts/tests/test_pre_authority_document_delta_admission.py",
    "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md",
))


def _tree(repo, index):
    return git_bytes(repo, ["write-tree"], index).decode("ascii").strip()


def _ref(repo):
    result = subprocess.run(["git", "-C", str(repo), "symbolic-ref", "--quiet", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return result.stdout.decode("ascii").strip() if result.returncode == 0 else None


def _binding(repo):
    ref = _ref(repo)
    return (ref, git_bytes(repo, ["rev-parse", ref]).decode("ascii").strip()) if ref else None


def _ceremony_lock(repo):
    raw = Path(git_bytes(repo, ["rev-parse", "--git-path", "pre-authority-admission.lock"]).decode().strip())
    path = raw if raw.is_absolute() else repo / raw
    try:
        return path, os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ValueError("DOCS_HEAD_CHANGED") from error


def _cas_ref(repo, ref, old, new):
    try:
        git_bytes(repo, ["update-ref", ref, new, old])
    except ValueError as error:
        raise ValueError("DOCS_HEAD_CHANGED") from error


def _raw_diff(repo, index, head):
    fields = git_bytes(repo, ["diff-index", "--cached", "--raw", "-z", head], index).split(b"\0")
    result = {}
    for meta, raw_path in zip(fields[::2], fields[1::2]):
        values = meta.decode("ascii").split()
        if len(values) != 5:
            raise ValueError("DOCS_ADMISSION_DIFF_INVALID")
        old_mode, new_mode, state = values[0].lstrip(":"), values[1], values[-1]
        if (state == "A" and (old_mode, new_mode) != ("000000", "100644")) or (state == "M" and (old_mode, new_mode) != ("100644", "100644")) or state not in {"A", "M"}:
            raise ValueError("DOCS_ADMISSION_DIFF_INVALID")
        path = safe_path(raw_path)
        result[path] = {"operation": "add" if state == "A" else "modify", "mode": new_mode, "blob_oid": values[3]}
    return result


def _manifest_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _oid(value, size=40):
    return isinstance(value, str) and len(value) == size and all(char in "0123456789abcdef" for char in value)


def prepare_pre_authority_admission(repo: Path, changes: dict[str, bytes], reviewed_allowlist: dict, review_manifest_path: Path):
    """Create only a temporary candidate index bound to independent reviewed identities."""
    if (not isinstance(changes, dict) or set(changes) != set(reviewed_allowlist)
            or set(changes) != TASK1_LITERAL_ALLOWLIST or review_manifest_path.is_relative_to(repo)):
        raise ValueError("DOCS_ADMISSION_ALLOWLIST_INVALID")
    binding = _binding(repo)
    if binding is None:
        raise ValueError("DOCS_ADMISSION_DETACHED_HEAD")
    ref, parent = binding
    directory = tempfile.TemporaryDirectory(prefix="gocode-pre-authority-", dir="/srv/data")
    index = Path(directory.name) / "candidate.index"
    git_bytes(repo, ["read-tree", parent], index)
    for path, content in changes.items():
        if not isinstance(content, bytes) or path in BASE_DIGESTS:
            directory.cleanup(); raise ValueError("DOCS_ADMISSION_ALLOWLIST_INVALID")
        oid = git_bytes(repo, ["hash-object", "-w", "--stdin"], stdin=content).decode("ascii").strip()
        git_bytes(repo, ["update-index", "--add", "--cacheinfo", f"100644,{oid},{path}"], index)
    try:
        paths = _raw_diff(repo, index, parent)
    except ValueError:
        directory.cleanup()
        raise
    for path, record in paths.items():
        record["blob_sha256"] = digest(changes[path])
    if paths != reviewed_allowlist:
        directory.cleanup(); raise ValueError("DOCS_ADMISSION_REVIEW_MISMATCH")
    snapshot = CandidateSnapshot.capture(repo, index_file=index)
    if snapshot.head_oid != parent or _binding(repo) != binding:
        directory.cleanup(); raise ValueError("DOCS_HEAD_CHANGED")
    _immutable(snapshot)
    if _select(snapshot) != "pre_authority":
        directory.cleanup(); raise ValueError("DOCS_ADMISSION_ALLOWLIST_INVALID")
    _validate_pre(snapshot)
    if _binding(repo) != binding:
        directory.cleanup(); raise ValueError("DOCS_HEAD_CHANGED")
    manifest = {"parent_head_oid": parent, "ref": ref, "candidate_tree_oid": _tree(repo, index), "paths": paths}
    raw = _manifest_bytes(manifest)
    review_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    review_manifest_path.write_bytes(raw)
    return {"temporary_directory": directory, "index_file": index, "manifest_path": review_manifest_path, "manifest_sha256": digest(raw)}


def commit_pre_authority_admission(repo: Path, prepared, message: str, reviewed_manifest_sha256: str, *, allow_commit: bool = False):
    """Create an exact candidate commit; this API never updates a ref."""
    if allow_commit is not True:
        raise ValueError("DOCS_ADMISSION_COMMIT_REQUIRES_PHASE_C")
    path, index = prepared.get("manifest_path"), prepared.get("index_file")
    if not isinstance(path, Path) or not isinstance(index, Path):
        raise ValueError("DOCS_ADMISSION_TREE_CHANGED")
    raw = path.read_bytes()
    if digest(raw) != reviewed_manifest_sha256:
        raise ValueError("DOCS_ADMISSION_MANIFEST_CHANGED")
    manifest = strict_json(raw, "DOCS_ADMISSION_MANIFEST_CHANGED")
    binding = (manifest.get("ref"), manifest.get("parent_head_oid"))
    if _binding(repo) != binding:
        raise ValueError("DOCS_HEAD_CHANGED")
    actual = _raw_diff(repo, index, manifest["parent_head_oid"])
    for record in actual.values():
        record["blob_sha256"] = digest(git_bytes(repo, ["cat-file", "blob", record["blob_oid"]]))
    if actual != manifest.get("paths") or _tree(repo, index) != manifest.get("candidate_tree_oid") or _binding(repo) != binding:
        raise ValueError("DOCS_ADMISSION_DIFF_INVALID")
    commit = git_bytes(repo, ["commit-tree", manifest["candidate_tree_oid"], "-p", manifest["parent_head_oid"], "-m", message]).decode("ascii").strip()
    return {"status": "BLOCKED_AT_MANUAL_REF_ADMISSION", "candidate_commit_oid": commit, "candidate_tree_oid": manifest["candidate_tree_oid"], "parent_head_oid": manifest["parent_head_oid"], "ref": manifest["ref"], "manifest_sha256": reviewed_manifest_sha256, "message_sha256": digest((message + "\n").encode())}


def admit_pre_authority_candidate(repo: Path, prepared, candidate: dict, reviewed_manifest_sha256: str, *, manual_ref_admission: bool = False):
    """CAS exactly one independently reviewed candidate after manual quiescence."""
    if manual_ref_admission is not True and manual_ref_admission is not False:
        raise ValueError("DOCS_ADMISSION_MANUAL_REF_INVALID")
    fields = {"status", "candidate_commit_oid", "candidate_tree_oid", "parent_head_oid", "ref", "manifest_sha256", "message_sha256"}
    path = prepared.get("manifest_path") if isinstance(prepared, dict) else None
    if (not isinstance(candidate, dict) or set(candidate) != fields or not isinstance(path, Path) or not _oid(reviewed_manifest_sha256, 64)
            or not all(_oid(candidate[key]) for key in ("candidate_commit_oid", "candidate_tree_oid", "parent_head_oid"))
            or not _oid(candidate["manifest_sha256"], 64) or not _oid(candidate["message_sha256"], 64)
            or not isinstance(candidate["ref"], str) or not candidate["ref"].startswith("refs/") or digest(path.read_bytes()) != reviewed_manifest_sha256 or candidate["manifest_sha256"] != reviewed_manifest_sha256):
        raise ValueError("DOCS_ADMISSION_MANIFEST_CHANGED")
    manifest, binding = strict_json(path.read_bytes(), "DOCS_ADMISSION_MANIFEST_CHANGED"), (candidate["ref"], candidate["parent_head_oid"])
    if candidate["status"] != "BLOCKED_AT_MANUAL_REF_ADMISSION" or (manifest.get("ref"), manifest.get("parent_head_oid"), manifest.get("candidate_tree_oid")) != (candidate["ref"], candidate["parent_head_oid"], candidate["candidate_tree_oid"]):
        raise ValueError("DOCS_ADMISSION_TREE_CHANGED")
    raw = git_bytes(repo, ["cat-file", "commit", candidate["candidate_commit_oid"]])
    try:
        header, body = raw.split(b"\n\n", 1)
    except ValueError as error:
        raise ValueError("DOCS_ADMISSION_TREE_CHANGED") from error
    lines = header.splitlines()
    if lines.count(("tree " + candidate["candidate_tree_oid"]).encode()) != 1 or [line[7:] for line in lines if line.startswith(b"parent ")] != [candidate["parent_head_oid"].encode()] or digest(body) != candidate["message_sha256"]:
        raise ValueError("DOCS_ADMISSION_TREE_CHANGED")
    if manual_ref_admission is False:
        return candidate
    lock_path, descriptor = _ceremony_lock(repo)
    try:
        if _binding(repo) != binding:
            raise ValueError("DOCS_HEAD_CHANGED")
        _cas_ref(repo, candidate["ref"], candidate["parent_head_oid"], candidate["candidate_commit_oid"])
        if _binding(repo) != (candidate["ref"], candidate["candidate_commit_oid"]):
            raise ValueError("DOCS_HEAD_CHANGED")
        return candidate["candidate_commit_oid"]
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)
