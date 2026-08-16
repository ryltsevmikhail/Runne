"""Pinned upgrade-only V4 overlay for the desktop-foundation document set."""
from __future__ import annotations
OVERLAY_V4_SCHEMA_PATH = "docs/schemas/pre-authority-document-overlay-v4.schema.json"
OVERLAY_V4_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V4.json"
OVERLAY_V4_SCHEMA_SHA256 = "b01e86ddda666752664e9967e8aa2b57a91a9968edeecdb63a046651e2379670"
OVERLAY_V4_ARTIFACT_SHA256 = "916acbface3808a20a76960d23e64ea99c664005b74314ef50e242ab958944f8"
OVERLAY_V4_PREDECESSOR = "6d19701767edd8ee9c6487bfe7105ca7d3dc8a4e"
OVERLAY_V4_PREDECESSOR_TREE = "2fcf58abb3da24b83e3605e8fd66d42530a15dad"
OVERLAY_V4_PREDECESSOR_SHA256 = "c23e10099d3e1729eb56d87391dad961631ee0094ec8a11d93e6456ed0be339c"
OVERLAY_V4_PREDECESSOR_TREE_SHA256 = "7cf44061a075ac52f323c660507eb24d80228afd2bd6372dd8e1946633755b48"
OVERLAY_V4_FOUNDATION = "42faee3c5acb86899471ac85861779e7c361709e"
OVERLAY_V4_FOUNDATION_TREE = "b0b49c736f65a2ae97f28e2aef50921cd049fa93"
OVERLAY_V4_FOUNDATION_SHA256 = "9c9bfd6ad862c1faa2dfab8c4f7c7247236e3d481a1c7942bde454ed26794892"
OVERLAY_V4_FOUNDATION_TREE_SHA256 = "83279478ff0c5bae5582c946243de0e9f358c1ab06b6bcf7c396f0e32ca307c7"
OVERLAY_V4_INTEGRATION = "c7cfefe70deca49efb5f4794e9ce98fc4b8c489a"
OVERLAY_V4_INTEGRATION_TREE = "25b5df0e981b6ad03f6a8a3852535e125ffbdbe0"
OVERLAY_V4_INTEGRATION_SHA256 = "c8ea6e171478e17151aaf8908aa3e137a1e0bf31bc83f838e1dc4218446ca23c"
OVERLAY_V4_INTEGRATION_TREE_SHA256 = "46f08db2f05028fd452b8725b2fdad10007a982fb491eda046a58b582e5eb087"
OVERLAY_V4_POLICY_ID = "gocode.project-owner.pre-authority-document-overlay-policy/4"
OVERLAY_V4_FROZEN_PROTECTED = {
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-6-report.md": ["DOCS_AUTHORIZING_CLAIM"],
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-7-report.md": ["DOCS_AUTHORIZING_CLAIM"],
    "docs/03-subsystems/local-engine/INTERFACES.md": ["DOCS_PROTECTED_CONFUSABLE"],
    "docs/adr/ADR-0030-supervised-bundled-local-inference-host.md": ["DOCS_AUTHORIZING_CLAIM"],
    "docs/desktop/adr/ADR-0009-client-runtime-transport.md": ["DOCS_AUTHORIZING_CLAIM"],
    "docs/desktop/adr/ADR-0016-daemon-provider-readiness.md": ["DOCS_AUTHORIZING_CLAIM"],
    "docs/desktop/adr/ADR-0017-replay-retention-baseline.md": ["DOCS_AUTHORIZING_CLAIM"],
}
OVERLAY_V4_ADD_PATHS = frozenset((
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/progress.md",
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-2-report.md",
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-4-report.md",
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-5-report.md",
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-6-report.md",
    ".superpowers/sdd/2026-08-10-desktop-v1-foundation/task-7-report.md",
    "docs/03-subsystems/local-engine/COMPATIBILITY.md", "docs/03-subsystems/local-engine/DOMAIN_MODEL.md",
    "docs/03-subsystems/local-engine/ERRORS.md", "docs/03-subsystems/local-engine/EVENTS.md",
    "docs/03-subsystems/local-engine/INTERFACES.md", "docs/03-subsystems/local-engine/LIFECYCLE.md",
    "docs/03-subsystems/local-engine/MODEL_MANIFEST.md", "docs/03-subsystems/local-engine/OPEN_QUESTIONS.md",
    "docs/03-subsystems/local-engine/PHASES.md", "docs/03-subsystems/local-engine/PROTOCOL.md",
    "docs/03-subsystems/local-engine/README.md", "docs/03-subsystems/local-engine/REQUIREMENTS.md",
    "docs/03-subsystems/local-engine/RESOURCE_MANAGEMENT.md", "docs/03-subsystems/local-engine/SECURITY.md",
    "docs/03-subsystems/local-engine/TEST_PLAN.md", "docs/03-subsystems/local-engine/TRACEABILITY.md",
    "docs/04-api-and-compatibility/CLI.md", "docs/adr/ADR-0030-supervised-bundled-local-inference-host.md",
    "docs/desktop/adr/ADR-0017-replay-retention-baseline.md", "docs/desktop/adr/ADR-0016-daemon-provider-readiness.md",
    "docs/evidence/provenance/desktop-native-platform-v1/README.md",
    "docs/superpowers/plans/2026-08-10-desktop-v1-foundation.md",
    "docs/superpowers/plans/2026-08-10-gocode-local-engine-phase1.md",
    "docs/superpowers/specs/2026-08-10-desktop-v1-frontend-completion-design.md",
    "docs/superpowers/specs/2026-08-10-gocode-local-engine-design.md",
    "docs/superpowers/plans/2026-08-10-desktop-operational-telemetry.md",
    "docs/superpowers/plans/2026-08-10-macos-bundled-provider-activation.md",
    "docs/superpowers/plans/2026-08-10-taskrun-read-replay-core.md",
    "docs/superpowers/specs/2026-08-10-desktop-parallel-slices-design.md",
))
OVERLAY_V4_REPLACEMENTS = frozenset((
    "docs/03-subsystems/README.md", "docs/DOCUMENTATION_MAP.md", "docs/README.md", "docs/STATUS.md",
    "docs/adr/README.md", "docs/decisions/DECISION_LOG.md", "docs/decisions/OPEN_QUESTIONS.md",
    "docs/desktop/02-architecture/CLIENT_STATE_MODEL.md", "docs/desktop/02-architecture/RUST_HOST_ARCHITECTURE.md",
    "docs/desktop/02-architecture/SYSTEM_OVERVIEW.md", "docs/desktop/05-runtime-integration/CLIENT_RUNTIME_CONTRACT.md",
    "docs/desktop/05-runtime-integration/COMPATIBILITY_MATRIX.md",
    "docs/desktop/05-runtime-integration/TRANSPORT_AUTH_AND_VERSION_PROFILE.md",
    "docs/desktop/05-runtime-integration/schemas/README.md", "docs/desktop/STATUS.md",
    "docs/desktop/adr/ADR-0009-client-runtime-transport.md", "docs/desktop/adr/README.md",
    "docs/desktop/decisions/DECISION_LOG.md", "docs/desktop/decisions/OPEN_QUESTIONS.md",
    "docs/desktop/matrices/REQUIREMENTS_TRACEABILITY.md", "docs/matrices/REQUIREMENTS_TRACEABILITY.md",
    "docs/schemas/README.md",
))
OVERLAY_V4_DOCUMENT_PATHS = OVERLAY_V4_ADD_PATHS | OVERLAY_V4_REPLACEMENTS
OVERLAY_V4_FIELDS = frozenset((
    "schema_version", "repository_id", "policy_id", "mode", "predecessor_commit_oid", "predecessor_tree_oid",
    "predecessor_commit_bytes_sha256", "predecessor_tree_bytes_sha256", "foundation_commit_oid", "foundation_tree_oid",
    "foundation_commit_bytes_sha256", "foundation_tree_bytes_sha256", "integration_anchor_commit_oid",
    "integration_anchor_tree_oid", "integration_anchor_commit_bytes_sha256", "integration_anchor_tree_bytes_sha256",
    "v1_schema_sha256", "v2_schema_sha256", "v2_artifact_sha256", "v3_schema_sha256", "v3_artifact_sha256",
    "base_universe_bytes_sha256", "base_governed_scope_bytes_sha256",
    "base_status_claims_bytes_sha256", "records", "status_claims",
))
OVERLAY_V4_PINS = {
    "schema_version": 4, "repository_id": "gocode", "policy_id": OVERLAY_V4_POLICY_ID,
    "mode": "pre_authority_overlay_desktop_foundation", "predecessor_commit_oid": OVERLAY_V4_PREDECESSOR,
    "predecessor_tree_oid": OVERLAY_V4_PREDECESSOR_TREE, "predecessor_commit_bytes_sha256": OVERLAY_V4_PREDECESSOR_SHA256,
    "predecessor_tree_bytes_sha256": OVERLAY_V4_PREDECESSOR_TREE_SHA256, "foundation_commit_oid": OVERLAY_V4_FOUNDATION,
    "foundation_tree_oid": OVERLAY_V4_FOUNDATION_TREE, "foundation_commit_bytes_sha256": OVERLAY_V4_FOUNDATION_SHA256,
    "foundation_tree_bytes_sha256": OVERLAY_V4_FOUNDATION_TREE_SHA256, "integration_anchor_commit_oid": OVERLAY_V4_INTEGRATION,
    "integration_anchor_tree_oid": OVERLAY_V4_INTEGRATION_TREE, "integration_anchor_commit_bytes_sha256": OVERLAY_V4_INTEGRATION_SHA256,
    "integration_anchor_tree_bytes_sha256": OVERLAY_V4_INTEGRATION_TREE_SHA256, "v1_schema_sha256": OVERLAY_V1_SCHEMA_SHA256,
    "v2_schema_sha256": OVERLAY_SCHEMA_SHA256, "v2_artifact_sha256": OVERLAY_V3_PINS["v2_artifact_sha256"], "v3_schema_sha256": OVERLAY_V3_SCHEMA_SHA256,
    "v3_artifact_sha256": OVERLAY_V3_ARTIFACT_SHA256,
}


def _v4_anchor(snapshot):
    pins = ((OVERLAY_V4_PREDECESSOR, OVERLAY_V4_PREDECESSOR_TREE, OVERLAY_V4_PREDECESSOR_SHA256, OVERLAY_V4_PREDECESSOR_TREE_SHA256),
            (OVERLAY_V4_FOUNDATION, OVERLAY_V4_FOUNDATION_TREE, OVERLAY_V4_FOUNDATION_SHA256, OVERLAY_V4_FOUNDATION_TREE_SHA256),
            (OVERLAY_V4_INTEGRATION, OVERLAY_V4_INTEGRATION_TREE, OVERLAY_V4_INTEGRATION_SHA256, OVERLAY_V4_INTEGRATION_TREE_SHA256))
    for commit, tree, commit_digest, tree_digest in pins:
        if (git_bytes(snapshot.repo, ["rev-parse", commit]).decode().strip() != commit
                or git_bytes(snapshot.repo, ["rev-parse", f"{commit}^{{tree}}"]).decode().strip() != tree
                or digest(git_bytes(snapshot.repo, ["cat-file", "commit", commit])) != commit_digest
                or digest(git_bytes(snapshot.repo, ["cat-file", "tree", tree])) != tree_digest):
            raise ValueError("OVERLAY_V4_LINEAGE")
    entries = {}
    for raw in filter(None, git_bytes(snapshot.repo, ["ls-tree", "-r", "-z", OVERLAY_V4_PREDECESSOR]).split(b"\0")):
        metadata, raw_path = raw.split(b"\t", 1)
        mode, _, oid = metadata.decode("ascii").split(" ")
        entries[safe_path(raw_path)] = (mode, oid)
    return entries


def _v4_expected(snapshot, anchor):
    replacements = set()
    for path, original in anchor.items():
        if not path.endswith((".md", ".markdown")) or original[0] != "100644":
            continue
        candidate = snapshot.entries.get(path)
        if candidate is None or candidate.mode != "100644":
            raise ValueError("DOCS_DELTA_DELETION")
        if (candidate.mode, candidate.oid) != original:
            if path not in OVERLAY_V4_REPLACEMENTS:
                raise ValueError("DOCS_BASE_MUTATION")
            replacements.add(path)
    additions = {path for path, entry in snapshot.entries.items() if path.endswith((".md", ".markdown")) and path not in anchor and entry.mode == "100644"}
    if additions != OVERLAY_V4_ADD_PATHS or replacements != OVERLAY_V4_REPLACEMENTS:
        raise ValueError("OVERLAY_V4_ADDITION_POLICY")
    return additions, replacements


def _v4_record(snapshot, record, anchor, additions, replacements):
    if not isinstance(record, dict) or set(record) != OVERLAY_RECORD_FIELDS:
        raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    path, operation = record.get("path"), record.get("operation")
    expected = additions if operation == "add" else replacements if operation == "replace" else set()
    entry = snapshot.entries.get(path)
    state = "governed" if isinstance(path, str) and path.startswith("docs/") and "/plans/" not in path else "non_governed"
    reason = None if state == "governed" else "Outside the authoritative docs/ governance tree."
    if (path not in expected or entry is None or entry.mode != "100644" or record.get("change_id") != "OVERLAY_V4_DESKTOP_FOUNDATION"
            or record.get("candidate_mode") != entry.mode or record.get("candidate_blob_oid") != entry.oid
            or record.get("candidate_sha256") != digest(entry.blob_bytes) or record.get("classification") != state
            or record.get("reason") != reason):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    if operation == "add":
        if any(record.get(field) is not None for field in ("base_mode", "base_blob_oid", "base_sha256")):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    else:
        mode, oid = anchor[path]
        base = git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_V4_PREDECESSOR}:{path}"])
        if (record.get("base_mode"), record.get("base_blob_oid"), record.get("base_sha256")) != (mode, oid, digest(base)):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    return path


def _overlay_v4_lineage(snapshot):
    previous = _predecessor_mode(snapshot)
    if previous == "overlay_v3" and snapshot.head_oid == OVERLAY_V4_PREDECESSOR:
        return
    if previous != "overlay_v4":
        raise ValueError("OVERLAY_V4_LINEAGE")
    pending, seen = [snapshot.head_oid], set()
    while pending and len(seen) < 1024:
        current = pending.pop()
        if current == OVERLAY_V4_PREDECESSOR:
            return
        if current not in seen:
            seen.add(current); pending.extend(_raw_parents(snapshot, current))
    raise ValueError("OVERLAY_V4_LINEAGE")


def _validate_pre_authority_document_overlay_v4(snapshot):
    schema, artifact = snapshot.entries.get(OVERLAY_V4_SCHEMA_PATH), snapshot.entries.get(OVERLAY_V4_ARTIFACT_PATH)
    if (schema is None or artifact is None or schema.mode != "100644" or artifact.mode != "100644"
            or digest(schema.blob_bytes) != OVERLAY_V4_SCHEMA_SHA256 or digest(artifact.blob_bytes) != OVERLAY_V4_ARTIFACT_SHA256):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V4_SCHEMA")
    value = strict_json(artifact.blob_bytes, "PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    if not isinstance(value, dict) or set(value) != OVERLAY_V4_FIELDS or any(value.get(key) != expected for key, expected in OVERLAY_V4_PINS.items()):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    for field, path in zip(("base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256"), BASE_DIGESTS):
        if value.get(field) != BASE_DIGESTS[path]:
            raise ValueError("PRE_AUTHORITY_BASE_DIGEST")
    for path, expected in ((SCHEMA_PATH, OVERLAY_V1_SCHEMA_SHA256), (OVERLAY_SCHEMA_PATH, OVERLAY_SCHEMA_SHA256),
                           (OVERLAY_ARTIFACT_PATH, OVERLAY_V3_PINS["v2_artifact_sha256"])):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V4_FROZEN_PIN")
    for path, expected in ((OVERLAY_V3_SCHEMA_PATH, OVERLAY_V3_SCHEMA_SHA256), (OVERLAY_V3_ARTIFACT_PATH, OVERLAY_V3_ARTIFACT_SHA256)):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V4_V3_PIN")
    _overlay_v4_lineage(snapshot)
    anchor = _v4_anchor(snapshot)
    additions, replacements = _v4_expected(snapshot, anchor)
    records = value.get("records")
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V4_ARTIFACT")
    paths = [_v4_record(snapshot, record, anchor, additions, replacements) for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)) or set(paths) != additions | replacements:
        raise ValueError("OVERLAY_V4_EXACTNESS")
    _validate_claims(snapshot, value.get("status_claims"), set(paths), frozen_protected=OVERLAY_V4_FROZEN_PROTECTED)


def validate_pre_authority_document_overlay_v4(repo: Path, *, index_file: Path | None = None) -> None:
    snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
    _immutable(snapshot)
    if _select(snapshot) == "overlay_v4":
        _validate_pre_authority_document_overlay_v4(snapshot)


OVERLAY_TRANSACTION_PATHS["OVERLAY_V4_DESKTOP_FOUNDATION"] = frozenset((
    *OVERLAY_V4_DOCUMENT_PATHS, OVERLAY_V4_SCHEMA_PATH, OVERLAY_V4_ARTIFACT_PATH,
    "scripts/tests/test_pre_authority_document_overlay_admission.py", "scripts/tests/test_pre_authority_document_overlay_v4.py",
    "scripts/tests/test_adr_identity.py",
    "scripts/validate_docs_parts/adr_identity.inc", "scripts/validate_docs_parts/documentation_rules.inc",
    "scripts/validate_docs_parts/pre_authority_document_delta.inc", "scripts/validate_docs_parts/pre_authority_overlay_admission.inc",
    "scripts/validate_docs_parts/pre_authority_overlay_v4.inc", "scripts/validate_docs_parts/pre_authority_snapshot.inc",
))
OVERLAY_DELETIONS["OVERLAY_V4_DESKTOP_FOUNDATION"] = frozenset()
