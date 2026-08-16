"""Pinned upgrade-only V5 overlay for the 2026-08-16 docs-sync document set."""
from __future__ import annotations
OVERLAY_V5_SCHEMA_PATH = "docs/schemas/pre-authority-document-overlay-v5.schema.json"
OVERLAY_V5_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V5.json"
OVERLAY_V5_SCHEMA_SHA256 = "078b361246f18e15bc15cc98e3b8d5d0ec201b04841333c444b09357b25000b7"
OVERLAY_V5_ARTIFACT_SHA256 = "9177f113899138bc6274cc47427b6a8e9c93771cf845820237faa39030e926f4"
OVERLAY_V5_PREDECESSOR = "8fedcb8c6204a84b63d7d20e1884da466060d180"
OVERLAY_V5_PREDECESSOR_TREE = "4e40dece48b34b5e40b410073040d3966b51b7ff"
OVERLAY_V5_PREDECESSOR_SHA256 = "9cfb42a47cd57f0d8876aa200f0b8afeee785c77104dd879245731d1e7e1652d"
OVERLAY_V5_PREDECESSOR_TREE_SHA256 = "54d97b52e50deb6bbc1acf3dba658359ad417f6341fa1bc11c3d3f44946daffd"
OVERLAY_V5_FOUNDATION = "f392f6018cfee18f4a0b2a470cb35bdc8b436597"
OVERLAY_V5_FOUNDATION_TREE = "d21d099933bc106cb60defac955c56a3de61de9d"
OVERLAY_V5_FOUNDATION_SHA256 = "c6eb18f9dabee4ab075af24daaeebe1a140061ac174b89c9dc2546f5bca55900"
OVERLAY_V5_FOUNDATION_TREE_SHA256 = "3119209c03dbf4691200fad856ccfd46bf3e0d765f58b8aaf566ff72449f4e30"
OVERLAY_V5_INTEGRATION = "f392f6018cfee18f4a0b2a470cb35bdc8b436597"
OVERLAY_V5_INTEGRATION_TREE = "d21d099933bc106cb60defac955c56a3de61de9d"
OVERLAY_V5_INTEGRATION_SHA256 = "c6eb18f9dabee4ab075af24daaeebe1a140061ac174b89c9dc2546f5bca55900"
OVERLAY_V5_INTEGRATION_TREE_SHA256 = "3119209c03dbf4691200fad856ccfd46bf3e0d765f58b8aaf566ff72449f4e30"
OVERLAY_V5_POLICY_ID = "gocode.project-owner.pre-authority-document-overlay-policy/5"
OVERLAY_V5_FROZEN_PROTECTED = {}
OVERLAY_V5_ADD_PATHS = frozenset((
    ".github/workflows.disabled/README.md",
    "docs/research/HYBRID_ACQUISITION_RUNTIME_FIT.md",
))
OVERLAY_V5_REPLACEMENTS = frozenset((
    "AGENTS.md", "docs/adr/README.md", "docs/decisions/DECISION_LOG.md", "docs/desktop/STATUS.md",
    "docs/desktop/05-runtime-integration/CLIENT_RUNTIME_CONTRACT.md",
    "docs/desktop/05-runtime-integration/COMPATIBILITY_MATRIX.md",
    "docs/desktop/decisions/OPEN_QUESTIONS.md",
    "docs/research/README.md",
    "docs/superpowers/plans/2026-08-10-macos-bundled-provider-activation.md",
    "docs/superpowers/plans/2026-08-13-rc1-qualified-unsigned-implementation.md",
    "docs/superpowers/plans/2026-08-13-rc2-verified-signed-envelopes-implementation.md",
    "docs/superpowers/plans/2026-08-13-rc3-publication-authorization-implementation.md",
))
OVERLAY_V5_DOCUMENT_PATHS = OVERLAY_V5_ADD_PATHS | OVERLAY_V5_REPLACEMENTS
OVERLAY_V5_FIELDS = frozenset((
    "schema_version", "repository_id", "policy_id", "mode", "predecessor_commit_oid",
    "predecessor_tree_oid", "predecessor_commit_bytes_sha256", "predecessor_tree_bytes_sha256",
    "foundation_commit_oid", "foundation_tree_oid", "foundation_commit_bytes_sha256",
    "foundation_tree_bytes_sha256", "integration_anchor_commit_oid", "integration_anchor_tree_oid",
    "integration_anchor_commit_bytes_sha256", "integration_anchor_tree_bytes_sha256", "v1_schema_sha256",
    "v2_schema_sha256", "v2_artifact_sha256", "v3_schema_sha256", "v3_artifact_sha256",
    "v4_schema_sha256", "v4_artifact_sha256", "base_universe_bytes_sha256",
    "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256", "records", "status_claims",
))
OVERLAY_V5_PINS = {
    "schema_version": 5, "repository_id": "gocode", "policy_id": OVERLAY_V5_POLICY_ID,
    "mode": "pre_authority_overlay_docs_sync_2026_08_16", "predecessor_commit_oid": OVERLAY_V5_PREDECESSOR,
    "predecessor_tree_oid": OVERLAY_V5_PREDECESSOR_TREE, "predecessor_commit_bytes_sha256": OVERLAY_V5_PREDECESSOR_SHA256,
    "predecessor_tree_bytes_sha256": OVERLAY_V5_PREDECESSOR_TREE_SHA256, "foundation_commit_oid": OVERLAY_V5_FOUNDATION,
    "foundation_tree_oid": OVERLAY_V5_FOUNDATION_TREE, "foundation_commit_bytes_sha256": OVERLAY_V5_FOUNDATION_SHA256,
    "foundation_tree_bytes_sha256": OVERLAY_V5_FOUNDATION_TREE_SHA256, "integration_anchor_commit_oid": OVERLAY_V5_INTEGRATION,
    "integration_anchor_tree_oid": OVERLAY_V5_INTEGRATION_TREE, "integration_anchor_commit_bytes_sha256": OVERLAY_V5_INTEGRATION_SHA256,
    "integration_anchor_tree_bytes_sha256": OVERLAY_V5_INTEGRATION_TREE_SHA256, "v1_schema_sha256": OVERLAY_V1_SCHEMA_SHA256,
    "v2_schema_sha256": OVERLAY_SCHEMA_SHA256, "v2_artifact_sha256": OVERLAY_V3_PINS["v2_artifact_sha256"],
    "v3_schema_sha256": OVERLAY_V3_SCHEMA_SHA256, "v3_artifact_sha256": OVERLAY_V3_ARTIFACT_SHA256,
    "v4_schema_sha256": OVERLAY_V4_SCHEMA_SHA256, "v4_artifact_sha256": OVERLAY_V4_ARTIFACT_SHA256,
}


def _v5_anchor(snapshot):
    pins = ((OVERLAY_V5_PREDECESSOR, OVERLAY_V5_PREDECESSOR_TREE, OVERLAY_V5_PREDECESSOR_SHA256, OVERLAY_V5_PREDECESSOR_TREE_SHA256),
            (OVERLAY_V5_FOUNDATION, OVERLAY_V5_FOUNDATION_TREE, OVERLAY_V5_FOUNDATION_SHA256, OVERLAY_V5_FOUNDATION_TREE_SHA256),
            (OVERLAY_V5_INTEGRATION, OVERLAY_V5_INTEGRATION_TREE, OVERLAY_V5_INTEGRATION_SHA256, OVERLAY_V5_INTEGRATION_TREE_SHA256))
    for commit, tree, commit_digest, tree_digest in pins:
        if (git_bytes(snapshot.repo, ["rev-parse", commit]).decode().strip() != commit
                or git_bytes(snapshot.repo, ["rev-parse", f"{commit}^{{tree}}"]).decode().strip() != tree
                or digest(git_bytes(snapshot.repo, ["cat-file", "commit", commit])) != commit_digest
                or digest(git_bytes(snapshot.repo, ["cat-file", "tree", tree])) != tree_digest):
            raise ValueError("OVERLAY_V5_LINEAGE")
    entries = {}
    for raw in filter(None, git_bytes(snapshot.repo, ["ls-tree", "-r", "-z", OVERLAY_V5_PREDECESSOR]).split(b"\0")):
        metadata, raw_path = raw.split(b"\t", 1)
        mode, _, oid = metadata.decode("ascii").split(" ")
        entries[safe_path(raw_path)] = (mode, oid)
    return entries


def _v5_expected(snapshot, anchor):
    replacements = set()
    for path, original in anchor.items():
        if not path.endswith((".md", ".markdown")) or original[0] != "100644":
            continue
        candidate = snapshot.entries.get(path)
        if candidate is None or candidate.mode != "100644":
            raise ValueError("DOCS_DELTA_DELETION")
        if (candidate.mode, candidate.oid) != original:
            if path not in OVERLAY_V5_REPLACEMENTS:
                raise ValueError("DOCS_BASE_MUTATION")
            replacements.add(path)
    additions = {path for path, entry in snapshot.entries.items() if path.endswith((".md", ".markdown")) and path not in anchor and entry.mode == "100644"}
    if additions != OVERLAY_V5_ADD_PATHS or replacements != OVERLAY_V5_REPLACEMENTS:
        raise ValueError("OVERLAY_V5_ADDITION_POLICY")
    return additions, replacements


def _v5_record(snapshot, record, anchor, additions, replacements):
    if not isinstance(record, dict) or set(record) != OVERLAY_RECORD_FIELDS:
        raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    path, operation = record.get("path"), record.get("operation")
    expected = additions if operation == "add" else replacements if operation == "replace" else set()
    entry = snapshot.entries.get(path)
    state = "governed" if isinstance(path, str) and path.startswith("docs/") and "/plans/" not in path else "non_governed"
    reason = None if state == "governed" else "Outside the authoritative docs/ governance tree."
    if (path not in expected or entry is None or entry.mode != "100644" or record.get("change_id") != "OVERLAY_V5_DOCS_SYNC_2026_08_16"
            or record.get("candidate_mode") != entry.mode or record.get("candidate_blob_oid") != entry.oid
            or record.get("candidate_sha256") != digest(entry.blob_bytes) or record.get("classification") != state
            or record.get("reason") != reason):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    if operation == "add":
        if any(record.get(field) is not None for field in ("base_mode", "base_blob_oid", "base_sha256")):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    else:
        mode, oid = anchor[path]
        base = git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_V5_PREDECESSOR}:{path}"])
        if (record.get("base_mode"), record.get("base_blob_oid"), record.get("base_sha256")) != (mode, oid, digest(base)):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    return path


def _overlay_v5_lineage(snapshot):
    previous = _predecessor_mode(snapshot)
    if previous not in {"overlay_v4", "overlay_v5"}:
        raise ValueError("OVERLAY_V5_LINEAGE")
    pending, seen = [snapshot.head_oid], set()
    while pending and len(seen) < 1024:
        current = pending.pop()
        if current == OVERLAY_V5_PREDECESSOR:
            return
        if current not in seen:
            seen.add(current); pending.extend(_raw_parents(snapshot, current))
    raise ValueError("OVERLAY_V5_LINEAGE")


def _validate_pre_authority_document_overlay_v5(snapshot):
    schema, artifact = snapshot.entries.get(OVERLAY_V5_SCHEMA_PATH), snapshot.entries.get(OVERLAY_V5_ARTIFACT_PATH)
    if (schema is None or artifact is None or schema.mode != "100644" or artifact.mode != "100644"
            or digest(schema.blob_bytes) != OVERLAY_V5_SCHEMA_SHA256 or digest(artifact.blob_bytes) != OVERLAY_V5_ARTIFACT_SHA256):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V5_SCHEMA")
    value = strict_json(artifact.blob_bytes, "PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    if not isinstance(value, dict) or set(value) != OVERLAY_V5_FIELDS or any(value.get(key) != expected for key, expected in OVERLAY_V5_PINS.items()):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    for field, path in zip(("base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256"), BASE_DIGESTS):
        if value.get(field) != BASE_DIGESTS[path]:
            raise ValueError("PRE_AUTHORITY_BASE_DIGEST")
    for path, expected in ((SCHEMA_PATH, OVERLAY_V1_SCHEMA_SHA256), (OVERLAY_SCHEMA_PATH, OVERLAY_SCHEMA_SHA256),
                           (OVERLAY_ARTIFACT_PATH, OVERLAY_V3_PINS["v2_artifact_sha256"])):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V5_FROZEN_PIN")
    for path, expected in ((OVERLAY_V3_SCHEMA_PATH, OVERLAY_V3_SCHEMA_SHA256), (OVERLAY_V3_ARTIFACT_PATH, OVERLAY_V3_ARTIFACT_SHA256)):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V5_V3_PIN")
    for path, expected in ((OVERLAY_V4_SCHEMA_PATH, OVERLAY_V4_SCHEMA_SHA256), (OVERLAY_V4_ARTIFACT_PATH, OVERLAY_V4_ARTIFACT_SHA256)):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V5_V4_PIN")
    _overlay_v5_lineage(snapshot)
    anchor = _v5_anchor(snapshot)
    additions, replacements = _v5_expected(snapshot, anchor)
    records = value.get("records")
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V5_ARTIFACT")
    paths = [_v5_record(snapshot, record, anchor, additions, replacements) for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)) or set(paths) != additions | replacements:
        raise ValueError("OVERLAY_V5_EXACTNESS")
    _validate_claims(snapshot, value.get("status_claims"), set(paths), frozen_protected=OVERLAY_V5_FROZEN_PROTECTED)


def validate_pre_authority_document_overlay_v5(repo: Path, *, index_file: Path | None = None) -> None:
    snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
    _immutable(snapshot)
    if _select(snapshot) == "overlay_v5":
        _validate_pre_authority_document_overlay_v5(snapshot)


OVERLAY_TRANSACTION_PATHS["OVERLAY_V5_DOCS_SYNC_2026_08_16"] = frozenset((
    *OVERLAY_V5_DOCUMENT_PATHS, OVERLAY_V5_SCHEMA_PATH, OVERLAY_V5_ARTIFACT_PATH,
    "scripts/tests/test_pre_authority_document_overlay_admission.py", "scripts/tests/test_pre_authority_document_overlay_v5.py",
    "scripts/validate_docs_parts/pre_authority_document_delta.inc", "scripts/validate_docs_parts/pre_authority_overlay_admission.inc",
    "scripts/validate_docs_parts/pre_authority_overlay_v5.inc", "scripts/validate_docs_parts/pre_authority_snapshot.inc",
))
OVERLAY_DELETIONS["OVERLAY_V5_DOCS_SYNC_2026_08_16"] = frozenset()
