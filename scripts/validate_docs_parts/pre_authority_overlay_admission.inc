"""Exact, locally blocked admission for the pinned overlay-v2 policy."""
import json
import os
import tempfile


OVERLAY_TRANSACTION_PATHS = {
    "OVERLAY_V2_BOOTSTRAP": frozenset((
        "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json",
        "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json",
        "docs/schemas/pre-authority-document-overlay-v2.schema.json",
        "scripts/validate_docs_parts/pre_authority_document_delta.inc",
        "scripts/validate_docs_parts/pre_authority_snapshot.inc",
        "scripts/validate_docs_parts/pre_authority_overlay_v2.inc",
        "scripts/validate_docs_parts/pre_authority_overlay_admission.inc",
        "scripts/tests/test_pre_authority_document_overlay_v2.py",
        "scripts/tests/test_pre_authority_document_overlay_admission.py",
    )),
    "TASK_2": frozenset((
        "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json", "docs/schemas/README.md",
        "docs/schemas/project-owner-trust-config-v1.schema.json", "docs/schemas/project-owner-authority-receipt-v1.schema.json",
        "docs/schemas/project-owner-key-rotation-v1.schema.json", "docs/schemas/project-owner-encrypted-key-backup-v1.schema.json",
        "scripts/project_owner_authority/fixtures/v1/trust-config.json", "scripts/project_owner_authority/fixtures/v1/receipt.json",
        "scripts/project_owner_authority/fixtures/v1/rotation.json", "scripts/project_owner_authority/fixtures/v1/backup-metadata.json",
        "scripts/tests/test_project_owner_authority_schemas.py",
    )),
}
OVERLAY_DELETIONS = {"OVERLAY_V2_BOOTSTRAP": frozenset((ARTIFACT_PATH,)), "TASK_2": frozenset()}


def _overlay_ref(repo):
    raw = git_bytes(repo, ["symbolic-ref", "--quiet", "HEAD"]).decode().strip()
    return raw, git_bytes(repo, ["rev-parse", raw]).decode().strip()


def _object_format(repo):
    return git_bytes(repo, ["rev-parse", "--show-object-format"]).decode().strip()


def _oid_width(repo):
    return {"sha1": 40, "sha256": 64}.get(_object_format(repo))


def _overlay_raw_diff(repo, index, parent):
    raw, result = git_bytes(repo, ["diff-index", "--cached", "--raw", "--no-abbrev", "-z", parent], index).split(b"\0"), {}
    for meta, raw_path in zip(raw[::2], raw[1::2]):
        old_mode, new_mode, old_oid, new_oid, state = meta.decode().split()
        path = safe_path(raw_path)
        operation = {"A": "add", "M": "modify", "D": "delete"}.get(state)
        if operation is None or path in result:
            raise ValueError("OVERLAY_ADMISSION_DIFF")
        result[path] = {"operation": operation, "old_mode": old_mode[1:], "old_oid": old_oid, "new_mode": new_mode, "new_oid": new_oid}
    return result


def _admission_record(repo, record, width):
    for side in ("old", "new"):
        oid = record[f"{side}_oid"]
        record[f"{side}_sha256"] = None if oid == "0" * width else digest(git_bytes(repo, ["cat-file", "blob", oid]))
    return record


def _admission_expected(transaction, paths, width):
    fields = {"operation", "old_mode", "old_oid", "new_mode", "new_oid", "old_sha256", "new_sha256"}
    if transaction not in OVERLAY_TRANSACTION_PATHS or not isinstance(paths, dict) or set(paths) != OVERLAY_TRANSACTION_PATHS[transaction]:
        raise ValueError("OVERLAY_ADMISSION_PATHS")
    for path, record in paths.items():
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("OVERLAY_ADMISSION_DIFF")
        if width not in (40, 64) or any(not isinstance(record[key], str) or len(record[key]) != width or any(char not in "0123456789abcdef" for char in record[key]) for key in ("old_oid", "new_oid")):
            raise ValueError("OVERLAY_ADMISSION_DIFF")
        deletion = path in OVERLAY_DELETIONS[transaction]
        expected = "delete" if deletion else "modify" if record["old_oid"] != "0" * width else "add"
        modes = ("100644", "000000") if deletion else ("100644", "100644") if expected == "modify" else ("000000", "100644")
        if record["operation"] != expected or (record["old_mode"], record["new_mode"]) != modes:
            raise ValueError("OVERLAY_ADMISSION_DIFF")


def _overlay_manifest(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def prepare_pre_authority_overlay_admission(repo: Path, transaction: str, changes: dict[str, bytes], manifest_path: Path):
    required = OVERLAY_TRANSACTION_PATHS.get(transaction)
    if not isinstance(manifest_path, Path):
        raise ValueError("OVERLAY_ADMISSION_PATHS")
    manifest_path = manifest_path.resolve()
    if required is None or not isinstance(changes, dict) or set(changes) != required - OVERLAY_DELETIONS[transaction] or manifest_path.is_relative_to(repo.resolve()):
        raise ValueError("OVERLAY_ADMISSION_PATHS")
    try:
        ref, parent = _overlay_ref(repo)
        object_format, width = _object_format(repo), _oid_width(repo)
        if width is None:
            raise ValueError("OVERLAY_ADMISSION_HEAD")
    except ValueError as error:
        raise ValueError("OVERLAY_ADMISSION_HEAD") from error
    directory = tempfile.TemporaryDirectory(prefix="gocode-overlay-", dir="/srv/data")
    index = Path(directory.name) / "candidate.index"
    git_bytes(repo, ["read-tree", parent], index)
    for path in OVERLAY_DELETIONS[transaction]:
        git_bytes(repo, ["update-index", "--force-remove", path], index)
    for path, content in changes.items():
        if not isinstance(content, bytes):
            directory.cleanup(); raise ValueError("OVERLAY_ADMISSION_PATHS")
        oid = git_bytes(repo, ["hash-object", "-w", "--stdin"], stdin=content).decode().strip()
        git_bytes(repo, ["update-index", "--add", "--cacheinfo", f"100644,{oid},{path}"], index)
    try:
        paths = {path: _admission_record(repo, record, width) for path, record in _overlay_raw_diff(repo, index, parent).items()}
        _admission_expected(transaction, paths, width)
        snapshot = CandidateSnapshot.capture(repo, index_file=index)
        expected_mode = {"OVERLAY_V3_REPAIR": "overlay_v3", "OVERLAY_V4_DESKTOP_FOUNDATION": "overlay_v4", "OVERLAY_V5_DOCS_SYNC_2026_08_16": "overlay_v5"}.get(transaction, "overlay")
        if snapshot.head_oid != parent or _overlay_ref(repo) != (ref, parent) or _select(snapshot) != expected_mode:
            raise ValueError("OVERLAY_ADMISSION_HEAD")
        try:
            {"overlay": _validate_pre_authority_document_overlay_v2, "overlay_v3": _validate_pre_authority_document_overlay_v3, "overlay_v4": _validate_pre_authority_document_overlay_v4, "overlay_v5": _validate_pre_authority_document_overlay_v5}[expected_mode](snapshot)
        except ValueError as error:
            raise ValueError("OVERLAY_ADMISSION_VALIDATION") from error
        tree = git_bytes(repo, ["write-tree"], index).decode().strip()
        if _overlay_ref(repo) != (ref, parent):
            raise ValueError("OVERLAY_ADMISSION_HEAD")
    except Exception:
        directory.cleanup(); raise
    raw = _overlay_manifest({"transaction_id": transaction, "object_format": object_format, "ref": ref, "parent_head_oid": parent, "candidate_tree_oid": tree, "paths": paths})
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(raw)
    return {"temporary_directory": directory, "index_file": index, "manifest_path": manifest_path, "manifest_sha256": digest(raw)}


def _overlay_checked(repo, prepared, digest_value):
    if not isinstance(prepared, dict) or not isinstance(prepared.get("manifest_path"), Path) or not isinstance(prepared.get("index_file"), Path):
        raise ValueError("OVERLAY_ADMISSION_MANIFEST")
    raw = prepared["manifest_path"].read_bytes()
    if digest(raw) != digest_value:
        raise ValueError("OVERLAY_ADMISSION_MANIFEST")
    value = strict_json(raw, "OVERLAY_ADMISSION_MANIFEST")
    if set(value) != {"transaction_id", "object_format", "ref", "parent_head_oid", "candidate_tree_oid", "paths"}:
        raise ValueError("OVERLAY_ADMISSION_MANIFEST")
    try:
        if value["object_format"] != _object_format(repo):
            raise ValueError("OVERLAY_ADMISSION_MANIFEST")
        width = _oid_width(repo)
        _admission_expected(value["transaction_id"], value["paths"], width)
        paths = {path: _admission_record(repo, record, width) for path, record in _overlay_raw_diff(repo, prepared["index_file"], value["parent_head_oid"]).items()}
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("OVERLAY_ADMISSION_MANIFEST") from error
    if _overlay_ref(repo) != (value["ref"], value["parent_head_oid"]) or paths != value["paths"] or git_bytes(repo, ["write-tree"], prepared["index_file"]).decode().strip() != value["candidate_tree_oid"]:
        raise ValueError("OVERLAY_ADMISSION_HEAD")
    if value["transaction_id"] in {"OVERLAY_V3_REPAIR", "OVERLAY_V4_DESKTOP_FOUNDATION", "OVERLAY_V5_DOCS_SYNC_2026_08_16"}:
        snapshot = CandidateSnapshot.capture(repo, index_file=prepared["index_file"])
        expected_mode = {"OVERLAY_V3_REPAIR": "overlay_v3", "OVERLAY_V4_DESKTOP_FOUNDATION": "overlay_v4", "OVERLAY_V5_DOCS_SYNC_2026_08_16": "overlay_v5"}[value["transaction_id"]]
        if _select(snapshot) != expected_mode:
            raise ValueError("OVERLAY_ADMISSION_VALIDATION")
        try:
            {"overlay_v3": _validate_pre_authority_document_overlay_v3, "overlay_v4": _validate_pre_authority_document_overlay_v4, "overlay_v5": _validate_pre_authority_document_overlay_v5}[expected_mode](snapshot)
        except ValueError as error:
            raise ValueError("OVERLAY_ADMISSION_VALIDATION") from error
    return value


def commit_pre_authority_overlay_admission(repo: Path, prepared, message: str, manifest_sha256: str, *, allow_commit=False):
    if allow_commit is not True or not isinstance(message, str) or not isinstance(manifest_sha256, str):
        raise ValueError("OVERLAY_ADMISSION_COMMIT")
    value = _overlay_checked(repo, prepared, manifest_sha256)
    commit = git_bytes(repo, ["commit-tree", value["candidate_tree_oid"], "-p", value["parent_head_oid"], "-m", message]).decode().strip()
    raw_commit = git_bytes(repo, ["cat-file", "commit", commit])
    receipt = {"candidate_commit_oid": commit, "candidate_commit_raw_sha256": digest(raw_commit), "candidate_tree_oid": value["candidate_tree_oid"], "manifest_sha256": manifest_sha256, "message_sha256": digest((message + "\n").encode()), "parent_head_oid": value["parent_head_oid"], "ref": value["ref"]}
    receipt_path = prepared["manifest_path"].with_name(prepared["manifest_path"].name + ".candidate-receipt")
    receipt_raw = _overlay_manifest(receipt)
    receipt_path.write_bytes(receipt_raw)
    return {"status": "BLOCKED_AT_MANUAL_REF_ADMISSION", **receipt, "candidate_receipt_sha256": digest(receipt_raw)}


def admit_pre_authority_overlay_candidate(repo: Path, prepared, candidate, manifest_sha256: str, reviewed_candidate_receipt_sha256: str, *, manual_ref_admission=False):
    if manual_ref_admission is not True and manual_ref_admission is not False:
        raise ValueError("OVERLAY_ADMISSION_MANUAL")
    value = _overlay_checked(repo, prepared, manifest_sha256)
    receipt_path = prepared["manifest_path"].with_name(prepared["manifest_path"].name + ".candidate-receipt")
    try:
        receipt_raw = receipt_path.read_bytes()
        receipt = strict_json(receipt_raw, "OVERLAY_ADMISSION_RECEIPT")
    except (OSError, ValueError) as error:
        raise ValueError("OVERLAY_ADMISSION_RECEIPT") from error
    receipt_fields = {"candidate_commit_oid", "candidate_commit_raw_sha256", "candidate_tree_oid", "manifest_sha256", "message_sha256", "parent_head_oid", "ref"}
    fields = {"status", "candidate_receipt_sha256", *receipt_fields}
    oids = ("candidate_commit_oid", "candidate_tree_oid", "parent_head_oid")
    valid_oid = lambda item: isinstance(item, str) and len(item) == _oid_width(repo) and all(char in "0123456789abcdef" for char in item)
    if not isinstance(reviewed_candidate_receipt_sha256, str) or digest(receipt_raw) != reviewed_candidate_receipt_sha256 or not isinstance(candidate, dict) or set(candidate) != fields or set(receipt) != receipt_fields or candidate["status"] != "BLOCKED_AT_MANUAL_REF_ADMISSION" or candidate["candidate_receipt_sha256"] != reviewed_candidate_receipt_sha256 or any(candidate[key] != receipt[key] for key in receipt_fields) or not all(valid_oid(candidate[key]) for key in oids) or not all(isinstance(candidate[key], str) for key in ("ref", "manifest_sha256", "message_sha256", "candidate_commit_raw_sha256")) or any(candidate[key] != value[key] for key in ("candidate_tree_oid", "parent_head_oid", "ref")) or candidate["manifest_sha256"] != manifest_sha256:
        raise ValueError("OVERLAY_ADMISSION_TREE")
    try:
        raw = git_bytes(repo, ["cat-file", "commit", candidate["candidate_commit_oid"]])
    except ValueError as error:
        raise ValueError("OVERLAY_ADMISSION_TREE") from error
    header, body = raw.split(b"\n\n", 1)
    if digest(raw) != candidate["candidate_commit_raw_sha256"] or [line[5:] for line in header.splitlines() if line.startswith(b"tree ")] != [candidate["candidate_tree_oid"].encode()] or [line[7:] for line in header.splitlines() if line.startswith(b"parent ")] != [candidate["parent_head_oid"].encode()] or digest(body) != candidate["message_sha256"]:
        raise ValueError("OVERLAY_ADMISSION_TREE")
    if manual_ref_admission is False:
        return candidate
    lock = Path(git_bytes(repo, ["rev-parse", "--git-path", "pre-authority-overlay.lock"]).decode().strip())
    lock = lock if lock.is_absolute() else repo / lock
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ValueError("OVERLAY_ADMISSION_HEAD") from error
    try:
        if _overlay_ref(repo) != (candidate["ref"], candidate["parent_head_oid"]):
            raise ValueError("OVERLAY_ADMISSION_HEAD")
        try:
            git_bytes(repo, ["update-ref", candidate["ref"], candidate["candidate_commit_oid"], candidate["parent_head_oid"]])
        except ValueError as error:
            raise ValueError("OVERLAY_ADMISSION_HEAD") from error
        return candidate["candidate_commit_oid"]
    finally:
        os.close(descriptor); lock.unlink(missing_ok=True)
