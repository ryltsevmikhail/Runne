"""Pinned v2 overlay for the immutable pre-authority document set."""


OVERLAY_SCHEMA_PATH = "docs/schemas/pre-authority-document-overlay-v2.schema.json"
OVERLAY_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V2.json"
OVERLAY_ANCHOR_COMMIT = "f6d0b2d6a5ccdda83ed80f9d0daefa785b622266"
OVERLAY_ANCHOR_TREE = "99c8f97ae55c4912ad6097b8397e9743e62e33ab"
OVERLAY_ANCHOR_COMMIT_BYTES_SHA256 = "b49b9a24f6c3c0d619a08e2d3e65976b1f6a25adbe380689a7448405d855002c"
OVERLAY_ANCHOR_TREE_BYTES_SHA256 = "6dbd3b34b5243ca7f355e5fbb902b6286369860ac1a48631e946dda07de44f5b"
OVERLAY_V1_SCHEMA_SHA256 = "379d0c00d93af56a75be9f554e9cd58efd1d085eaabdebf8af1769b1ea66450f"
OVERLAY_V1_ARTIFACT_SHA256 = "b0f4a92f07df9efd78aebf5dee5ef682e6698ad92fc3b21957e37705ff817d54"
OVERLAY_SCHEMA_SHA256 = "2b38bd6681b8549991e185f13e37125d30a3034f6ee424f3ffae697cf27f944c"
OVERLAY_BASE_REPLACEMENTS = frozenset(("docs/schemas/README.md",))
OVERLAY_BASELINE_ADDITIONS = frozenset((
    "docs/adr/ADR-0027-v1-platform-scope.md", "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md", "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md", "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md",
    "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md", "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md",
))
OVERLAY_POLICY_ID = "gocode.project-owner.pre-authority-document-overlay-policy/2"
OVERLAY_FIELDS = frozenset(("schema_version", "repository_id", "policy_id", "mode", "anchor_commit_oid", "anchor_tree_oid", "anchor_commit_bytes_sha256", "anchor_tree_bytes_sha256", "v1_schema_sha256", "v1_artifact_sha256", "base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256", "records", "status_claims"))
OVERLAY_RECORD_FIELDS = frozenset(("operation", "change_id", "path", "candidate_mode", "candidate_blob_oid", "candidate_sha256", "base_mode", "base_blob_oid", "base_sha256", "classification", "reason"))


def _overlay_anchor(snapshot):
    if git_bytes(snapshot.repo, ["rev-parse", OVERLAY_ANCHOR_COMMIT]).decode().strip() != OVERLAY_ANCHOR_COMMIT or git_bytes(snapshot.repo, ["rev-parse", f"{OVERLAY_ANCHOR_COMMIT}^{{tree}}"]).decode().strip() != OVERLAY_ANCHOR_TREE:
        raise ValueError("OVERLAY_ANCHOR_PIN")
    if digest(git_bytes(snapshot.repo, ["cat-file", "commit", OVERLAY_ANCHOR_COMMIT])) != OVERLAY_ANCHOR_COMMIT_BYTES_SHA256 or digest(git_bytes(snapshot.repo, ["cat-file", "tree", OVERLAY_ANCHOR_TREE])) != OVERLAY_ANCHOR_TREE_BYTES_SHA256:
        raise ValueError("OVERLAY_ANCHOR_PIN")
    for path, expected in ((SCHEMA_PATH, OVERLAY_V1_SCHEMA_SHA256), (ARTIFACT_PATH, OVERLAY_V1_ARTIFACT_SHA256), *BASE_DIGESTS.items()):
        if digest(git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_ANCHOR_COMMIT}:{path}"])) != expected:
            raise ValueError("OVERLAY_ANCHOR_PIN")
    entries = {}
    for record in filter(None, git_bytes(snapshot.repo, ["ls-tree", "-r", "-z", OVERLAY_ANCHOR_COMMIT]).split(b"\0")):
        metadata, raw_path = record.split(b"\t", 1)
        mode, _, oid = metadata.decode("ascii").split(" ")
        entries[safe_path(raw_path)] = (mode, oid)
    return entries


def _overlay_expected(snapshot, base, anchor):
    replacements = set()
    for path in base:
        candidate, original = snapshot.entries.get(path), anchor.get(path)
        if original is None or candidate is None:
            raise ValueError("DOCS_BASE_MUTATION")
        if (candidate.mode, candidate.oid) != original:
            if path not in OVERLAY_BASE_REPLACEMENTS or candidate.mode != "100644":
                raise ValueError("DOCS_BASE_MUTATION")
            replacements.add(path)
    for path, (mode, _) in anchor.items():
        candidate = snapshot.entries.get(path)
        if path.endswith((".md", ".markdown")) and path not in base and mode == "100644" and (candidate is None or candidate.mode != "100644"):
            raise ValueError("DOCS_DELTA_DELETION")
    additions = _document_paths(snapshot, base)
    if additions != OVERLAY_BASELINE_ADDITIONS:
        raise ValueError("OVERLAY_ADDITION_POLICY")
    if any(entry.mode != "100644" for path, entry in snapshot.entries.items() if path.endswith((".md", ".markdown")) and path not in base):
        raise ValueError("DOCS_DELTA_ENTRY_INVALID")
    return additions, replacements


def _overlay_base_classifications(snapshot):
    value = strict_json(snapshot.bytes("docs/rc0/document-universe-v1.json"), "DOCS_UNIVERSE_INVALID")
    return {record["path"]: record["classification"] for record in value["paths"] if isinstance(record, dict) and set(record) >= {"path", "classification"}}


def _overlay_record(snapshot, record, anchor, additions, replacements, base_classifications):
    if not isinstance(record, dict) or record.get("operation") not in {"add", "replace"}:
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    if set(record) != OVERLAY_RECORD_FIELDS or not isinstance(record.get("path"), str):
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    path, entry = safe_path(record["path"].encode()), snapshot.entries.get(record["path"])
    expected = additions if record["operation"] == "add" else replacements
    change_id = "TASK_1_BASELINE" if record["operation"] == "add" else "TASK_2"
    if record.get("change_id") != change_id or path not in expected or entry is None or entry.mode != "100644" or record.get("candidate_mode") != entry.mode or record.get("candidate_blob_oid") != entry.oid or record.get("candidate_sha256") != digest(entry.blob_bytes):
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    state = base_classifications.get(path, _record_classification(path))
    if record.get("classification") != state or ((state == "governed" and record.get("reason") is not None) or (state == "non_governed" and record.get("reason") != "Outside the authoritative docs/ governance tree.")):
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    if record["operation"] == "replace":
        mode, oid = anchor[path]
        if record.get("base_mode") != mode or record.get("base_blob_oid") != oid or record.get("base_sha256") != digest(git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_ANCHOR_COMMIT}:{path}"])):
            raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    elif record.get("base_mode") is not None or record.get("base_blob_oid") is not None or record.get("base_sha256") is not None:
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    if record["operation"] == "add":
        mode, oid = anchor[path]
        if (entry.mode, entry.oid) != (mode, oid) or digest(entry.blob_bytes) != digest(git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_ANCHOR_COMMIT}:{path}"])):
            raise ValueError("OVERLAY_BASELINE_PIN")
    return path


def _raw_parents(snapshot, oid):
    raw = git_bytes(snapshot.repo, ["cat-file", "commit", oid])
    try:
        header, _ = raw.split(b"\n\n", 1)
    except ValueError as error:
        raise ValueError("OVERLAY_ANCHOR_PIN") from error
    return [line[7:].decode("ascii") for line in header.splitlines() if line.startswith(b"parent ")]


def _overlay_lineage(snapshot):
    previous = _predecessor_mode(snapshot)
    if previous == "repair":
        return
    if previous == "pre_authority" and snapshot.head_oid != OVERLAY_ANCHOR_COMMIT:
        raise ValueError("OVERLAY_ANCHOR_PIN")
    if previous == "overlay":
        pending, seen = [snapshot.head_oid], set()
        while pending and len(seen) < 1024:
            current = pending.pop()
            if current == OVERLAY_ANCHOR_COMMIT:
                return
            if current not in seen:
                seen.add(current)
                pending.extend(_raw_parents(snapshot, current))
        raise ValueError("OVERLAY_ANCHOR_PIN")


def _overlay_v1_schema(snapshot, anchor):
    entry, original = snapshot.entries.get(SCHEMA_PATH), anchor.get(SCHEMA_PATH)
    if entry is None or original is None or (entry.mode, entry.oid) != original or digest(entry.blob_bytes) != OVERLAY_V1_SCHEMA_SHA256:
        raise ValueError("OVERLAY_V1_SCHEMA_PIN")


def _validate_pre_authority_document_overlay_v2(snapshot):
    schema, artifact = snapshot.entries.get(OVERLAY_SCHEMA_PATH), snapshot.entries.get(OVERLAY_ARTIFACT_PATH)
    if schema is None or artifact is None or schema.mode != "100644" or artifact.mode != "100644" or digest(schema.blob_bytes) != OVERLAY_SCHEMA_SHA256:
        raise ValueError("PRE_AUTHORITY_OVERLAY_SCHEMA")
    value = strict_json(artifact.blob_bytes, "PRE_AUTHORITY_OVERLAY_ARTIFACT")
    pins = {"schema_version": 2, "repository_id": "gocode", "policy_id": OVERLAY_POLICY_ID, "mode": "pre_authority_overlay", "anchor_commit_oid": OVERLAY_ANCHOR_COMMIT, "anchor_tree_oid": OVERLAY_ANCHOR_TREE, "anchor_commit_bytes_sha256": OVERLAY_ANCHOR_COMMIT_BYTES_SHA256, "anchor_tree_bytes_sha256": OVERLAY_ANCHOR_TREE_BYTES_SHA256, "v1_schema_sha256": OVERLAY_V1_SCHEMA_SHA256, "v1_artifact_sha256": OVERLAY_V1_ARTIFACT_SHA256}
    if not isinstance(value, dict) or set(value) != OVERLAY_FIELDS or any(value.get(key) != expected for key, expected in pins.items()):
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    for field, path in zip(("base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256"), BASE_DIGESTS):
        if value.get(field) != BASE_DIGESTS[path]:
            raise ValueError("PRE_AUTHORITY_BASE_DIGEST")
    _overlay_lineage(snapshot)
    base, anchor = _base_paths(snapshot), _overlay_anchor(snapshot)
    _overlay_v1_schema(snapshot, anchor)
    additions, replacements = _overlay_expected(snapshot, base, anchor)
    records = value.get("records")
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_OVERLAY_ARTIFACT")
    base_classifications = _overlay_base_classifications(snapshot)
    paths = [_overlay_record(snapshot, record, anchor, additions, replacements, base_classifications) for record in records]
    if len(paths) != len(set(paths)) or paths != sorted(paths) or set(paths) != additions | replacements:
        raise ValueError("OVERLAY_EXACTNESS")
    _validate_claims(snapshot, value.get("status_claims"), set(paths))


def validate_pre_authority_document_overlay_v2(repo: Path, *, index_file: Path | None = None) -> None:
    snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
    _immutable(snapshot)
    if _select(snapshot) == "overlay":
        _validate_pre_authority_document_overlay_v2(snapshot)


exec((_parts_root / "pre_authority_overlay_admission.inc").read_text(encoding="utf-8"))
