"""Pinned V3 successor for the exact post-repair documentation candidate."""
OVERLAY_V3_SCHEMA_PATH = "docs/schemas/pre-authority-document-overlay-v3.schema.json"
OVERLAY_V3_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V3.json"
OVERLAY_V3_SCHEMA_SHA256 = "e74905818e36e9de9b0773f2d5c58304ca78e3c31a7ddd6e1e0bd40cec6a4273"
OVERLAY_V3_ARTIFACT_SHA256 = "c3e381d0de7ebb45506afc014047730b0fc7a872115273cc1f3883d52189cefd"
OVERLAY_V3_POLICY_ID = "gocode.project-owner.pre-authority-document-overlay-policy/3"
OVERLAY_V3_FROZEN_PROTECTED = {
    "docs/adr/ADR-0028-promotion-and-release-authority-v2.md": ["DOCS_AUTHORIZING_CLAIM"],
    "docs/authority/IMPLEMENTATION_VERIFICATION_2026-08-12.md": ["DOCS_AUTHORIZING_CLAIM"],
}
OVERLAY_V3_ADD_PATHS = (
    "crates/gocode-release-authority/README.md",
    "docs/adr/ADR-0027-v1-platform-scope.md", "docs/adr/ADR-0028-promotion-and-release-authority-v2.md",
    "docs/adr/ADR-0029-versioned-promotion-trust-and-evidence-authority.md",
    "docs/authority/IMPLEMENTATION_VERIFICATION_2026-08-12.md",
    "docs/authority/V1_PLATFORM_SCOPE_AUTHORIZATION_OPERATOR_CHECKLIST.md",
    "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md",
    "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md",
    "docs/superpowers/plans/2026-08-13-rc1-qualified-unsigned-implementation.md",
    "docs/superpowers/plans/2026-08-13-rc2-verified-signed-envelopes-implementation.md",
    "docs/superpowers/plans/2026-08-13-rc3-publication-authorization-implementation.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
    "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md",
    "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md",
    "docs/superpowers/specs/2026-08-13-post-rc0-delivery-program-design-v2.md",
    "docs/superpowers/specs/2026-08-13-rc1-qualified-unsigned-design.md",
    "docs/superpowers/specs/2026-08-13-rc2-verified-signed-envelopes-design.md",
    "docs/superpowers/specs/2026-08-13-rc3-publication-authorization-design.md",
    "scripts/project_owner_authority/fixtures/v2/initial-ceremony/README.md",
    "scripts/project_owner_authority/fixtures/v2/initial-ceremony/blobs/desktop-adr.md",
    "scripts/project_owner_authority/fixtures/v2/initial-ceremony/blobs/runtime-adr.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/README.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/ROADMAP.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/STATUS.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/adr/ADR-0010-sandbox-enforcement.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/adr/README.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/decisions/DECISION_LOG.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/decisions/OPEN_QUESTIONS.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/07-testing/CI_AND_PLATFORM_MATRIX.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/09-release/PLATFORM_SUPPORT.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/ROADMAP.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/STATUS.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/adr/ADR-0012-platform-support-floor.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/adr/README.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/decisions/DECISION_LOG.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/desktop/decisions/OPEN_QUESTIONS.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/matrices/REQUIREMENTS_TRACEABILITY.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_MANIFEST_V1.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/release/COMPATIBILITY_V1.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/release/POST_RC0_PLATFORM_QUALIFICATION_INTERFACE_V1.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/release/RELEASE_MANIFEST_V1.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-07-27-phase6-core-native-qualification-design.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-07-27-phase6-security-platform-design.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-07-28-phase10-release-qualification-design.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-07-31-production-capabilities-program-design.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
    "scripts/project_owner_authority/fixtures/v3/reconciliation/documents/docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
    "scripts/rc0_policy/fixtures/platform_claim_migration/v1/invalid/README.md",
)
OVERLAY_V3_REPLACEMENTS = (
    "docs/adr/README.md", "docs/decisions/DECISION_LOG.md",
    "docs/decisions/OPEN_QUESTIONS.md", "docs/desktop/adr/README.md",
    "docs/desktop/decisions/DECISION_LOG.md", "docs/desktop/decisions/OPEN_QUESTIONS.md",
    "docs/schemas/README.md",
)
OVERLAY_V3_FIELDS = frozenset((
    "schema_version", "repository_id", "policy_id", "mode", "anchor_commit_oid",
    "anchor_tree_oid", "anchor_commit_bytes_sha256", "anchor_tree_bytes_sha256",
    "v2_schema_sha256", "v2_artifact_sha256", "base_universe_bytes_sha256",
    "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256", "records",
    "status_claims",
))
OVERLAY_V3_RECORD_FIELDS = OVERLAY_RECORD_FIELDS
OVERLAY_V3_PINS = {
    "schema_version": 3, "repository_id": "gocode", "policy_id": OVERLAY_V3_POLICY_ID,
    "mode": "pre_authority_overlay_successor", "anchor_commit_oid": OVERLAY_ANCHOR_COMMIT,
    "anchor_tree_oid": OVERLAY_ANCHOR_TREE,
    "anchor_commit_bytes_sha256": OVERLAY_ANCHOR_COMMIT_BYTES_SHA256,
    "anchor_tree_bytes_sha256": OVERLAY_ANCHOR_TREE_BYTES_SHA256,
    "v2_schema_sha256": OVERLAY_SCHEMA_SHA256, "v2_artifact_sha256": "70e533bb5734b1f2e466932ab3f73a87eb875ef99f74e0cbfa44eb4dfbec2c67",
}
OVERLAY_TRANSACTION_PATHS["OVERLAY_V3_REPAIR"] = frozenset((
    ".gitignore", "crates/gocode-release-authority/src/store_durable_receipt.rs",
    "crates/project-owner-authority/src/trust_v4.rs", ARTIFACT_PATH,
    "docs/schemas/rc2-native-evidence-v1.schema.json", "docs/schemas/rc2-signing-effect-claim-v1.schema.json",
    "docs/schemas/rc2-signing-review-v1.schema.json", "docs/schemas/rc2-update-metadata-issuance-v1.schema.json",
    OVERLAY_V3_SCHEMA_PATH, OVERLAY_V3_ARTIFACT_PATH,
    "scripts/tests/test_pre_authority_document_delta.py", "scripts/tests/test_pre_authority_document_overlay_admission.py",
    "scripts/tests/test_pre_authority_document_overlay_v2.py", "scripts/tests/test_pre_authority_document_overlay_v3.py",
    "scripts/tests/test_release_authority_schema_parity.py", "scripts/tests/test_validate_docs_ignored_trees.py",
    "scripts/validate_docs_parts/pre_authority_document_delta.inc", "scripts/validate_docs_parts/pre_authority_overlay_admission.inc",
    "scripts/validate_docs_parts/pre_authority_overlay_repair.inc", "scripts/validate_docs_parts/pre_authority_overlay_v2.inc",
    "scripts/validate_docs_parts/pre_authority_overlay_v3.inc", "scripts/validate_docs_parts/pre_authority_snapshot.inc",
    "scripts/validate_docs_parts/repository_walk.py", "scripts/validate_docs_parts/schema_and_profile.inc",
))
OVERLAY_DELETIONS["OVERLAY_V3_REPAIR"] = frozenset((ARTIFACT_PATH, "crates/gocode-release-authority/src/store_durable_receipt.rs"))


def _v3_expected(snapshot, base, anchor):
    replacements = set()
    for path in base:
        candidate, original = snapshot.entries.get(path), anchor.get(path)
        if candidate is None or original is None:
            raise ValueError("DOCS_BASE_MUTATION")
        if (candidate.mode, candidate.oid) != original:
            if path not in OVERLAY_V3_REPLACEMENTS or candidate.mode != "100644":
                raise ValueError("DOCS_BASE_MUTATION")
            replacements.add(path)
    for path, (mode, _) in anchor.items():
        candidate = snapshot.entries.get(path)
        if path.endswith((".md", ".markdown")) and path not in base and mode == "100644" and (candidate is None or candidate.mode != "100644"):
            raise ValueError("DOCS_DELTA_DELETION")
    additions = _document_paths(snapshot, base)
    if additions != set(OVERLAY_V3_ADD_PATHS) or replacements != set(OVERLAY_V3_REPLACEMENTS):
        raise ValueError("OVERLAY_V3_ADDITION_POLICY")
    if any(entry.mode != "100644" for path, entry in snapshot.entries.items() if path.endswith((".md", ".markdown")) and path not in base):
        raise ValueError("DOCS_DELTA_ENTRY_INVALID")
    return additions, replacements


def _v3_record(snapshot, record, anchor, additions, replacements, classifications):
    if not isinstance(record, dict) or set(record) != OVERLAY_V3_RECORD_FIELDS:
        raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    path, entry = record.get("path"), snapshot.entries.get(record.get("path"))
    operation = record.get("operation")
    expected = additions if operation == "add" else replacements if operation == "replace" else set()
    change_id = "PRE_AUTHORITY_DOCUMENT_SUCCESSOR" if operation == "add" else "PRE_AUTHORITY_DOCUMENT_INDEX"
    state = classifications.get(path, _record_classification(path))
    if (path not in expected or entry is None or entry.mode != "100644"
            or record.get("change_id") != change_id or record.get("candidate_mode") != entry.mode
            or record.get("candidate_blob_oid") != entry.oid or record.get("candidate_sha256") != digest(entry.blob_bytes)
            or record.get("classification") != state
            or (state == "governed" and record.get("reason") is not None)
            or (state == "non_governed" and record.get("reason") != "Outside the authoritative docs/ governance tree.")):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    if operation == "add":
        if any(record.get(field) is not None for field in ("base_mode", "base_blob_oid", "base_sha256")):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    else:
        mode, oid = anchor[path]
        base = git_bytes(snapshot.repo, ["cat-file", "blob", f"{OVERLAY_ANCHOR_COMMIT}:{path}"])
        if (record.get("base_mode"), record.get("base_blob_oid"), record.get("base_sha256")) != (mode, oid, digest(base)):
            raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    return path


def _overlay_v3_lineage(snapshot):
    previous = _predecessor_mode(snapshot)
    if previous == "repair":
        return
    if previous != "overlay_v3":
        raise ValueError("OVERLAY_V3_LINEAGE")
    pending, seen = [snapshot.head_oid], set()
    while pending and len(seen) < 1024:
        current = pending.pop()
        if current == REPAIR_PREDECESSOR_COMMIT:
            return
        if current not in seen:
            seen.add(current)
            pending.extend(_raw_parents(snapshot, current))
    raise ValueError("OVERLAY_V3_LINEAGE")


def _validate_pre_authority_document_overlay_v3(snapshot):
    schema, artifact = snapshot.entries.get(OVERLAY_V3_SCHEMA_PATH), snapshot.entries.get(OVERLAY_V3_ARTIFACT_PATH)
    if (schema is None or artifact is None or schema.mode != "100644" or artifact.mode != "100644"
            or digest(schema.blob_bytes) != OVERLAY_V3_SCHEMA_SHA256
            or digest(artifact.blob_bytes) != OVERLAY_V3_ARTIFACT_SHA256):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V3_SCHEMA")
    value = strict_json(artifact.blob_bytes, "PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    if not isinstance(value, dict) or set(value) != OVERLAY_V3_FIELDS or any(value.get(key) != expected for key, expected in OVERLAY_V3_PINS.items()):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    for field, path in zip(("base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256"), BASE_DIGESTS):
        if value.get(field) != BASE_DIGESTS[path]:
            raise ValueError("PRE_AUTHORITY_BASE_DIGEST")
    for path, expected in ((OVERLAY_SCHEMA_PATH, OVERLAY_SCHEMA_SHA256), (OVERLAY_ARTIFACT_PATH, OVERLAY_V3_PINS["v2_artifact_sha256"])):
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("OVERLAY_V3_V2_PIN")
    _overlay_v3_lineage(snapshot)
    base, anchor = _base_paths(snapshot), _overlay_anchor(snapshot)
    _overlay_v1_schema(snapshot, anchor)
    additions, replacements = _v3_expected(snapshot, base, anchor)
    records = value.get("records")
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_OVERLAY_V3_ARTIFACT")
    classifications = _overlay_base_classifications(snapshot)
    paths = [_v3_record(snapshot, record, anchor, additions, replacements, classifications) for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)) or set(paths) != additions | replacements:
        raise ValueError("OVERLAY_V3_EXACTNESS")
    _validate_claims(snapshot, value.get("status_claims"), set(paths), frozen_protected=OVERLAY_V3_FROZEN_PROTECTED)


def validate_pre_authority_document_overlay_v3(repo: Path, *, index_file: Path | None = None) -> None:
    snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
    _immutable(snapshot)
    if _select(snapshot) == "overlay_v3":
        _validate_pre_authority_document_overlay_v3(snapshot)
