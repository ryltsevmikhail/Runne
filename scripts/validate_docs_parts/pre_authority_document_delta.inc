"""Pre-authority documentation mode dispatcher; all candidate bytes are frozen."""
from pathlib import Path
import re


_parts_root = Path(globals().get("BASE", Path(__file__).resolve().parents[2])) / "scripts" / "validate_docs_parts"
for _part in ("pre_authority_snapshot.inc", "pre_authority_claims.inc", "pre_authority_admission.inc", "pre_authority_legacy.inc", "pre_authority_composed_v3.inc"):
    exec((_parts_root / _part).read_text(encoding="utf-8"))


BASE_DIGESTS = {
    "docs/rc0/document-universe-v1.json": "efeb9eabdfb03084a8cdc10c33acc4f8008dd73e1f750acb24513d19d1ab66b1",
    "docs/rc0/governed-scope-v1.json": "18d80090ecc15ed0da8a935cbde1dfcc72308d96eb28cd0c0f9c0b6315daa5a4",
    "docs/rc0/status-claims-v1.json": "d0dbbe23dbb553d090751a4f43537fd50ea46c298bdc9008f4ef80896067e77b",
}
TASK1_BASE_DOCUMENT_OVERRIDE = {
    "docs/00-foundation/DOCUMENTATION_RULES.md": "aa6adbba8a9c6ffea16425bcdb31523e6ecf99f6242d81242aaadfc02f5f1bec",
}
SCHEMA_PATH = "docs/schemas/pre-authority-document-delta-v1.schema.json"
ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_DELTA_V1.json"
COMPOSED_PATH = "docs/rc0/POST_RC0_PLATFORM_QUALIFICATION_COMPOSED_UNIVERSE_V1.json"
SCHEMA_SHA256 = "379d0c00d93af56a75be9f554e9cd58efd1d085eaabdebf8af1769b1ea66450f"
ARTIFACT_FIELDS = frozenset(("schema_version", "repository_id", "mode", "base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256", "documents", "status_claims"))
DOCUMENT_FIELDS = frozenset(("path", "classification", "sha256", "reason"))
CLAIM_FIELDS = frozenset(("path", "claim_kind", "disposition", "evidence_binding"))
EVIDENCE_PROFILE = "gocode.rc0.evidence-profile/3"
GOVERNED_DELTA_PATHS = frozenset((
    "docs/adr/ADR-0027-v1-platform-scope.md",
    "docs/desktop/adr/ADR-0015-v1-platform-scope.md",
    "docs/superpowers/plans/2026-08-09-v1-platform-scope-local-contracts.md",
    "docs/superpowers/plans/2026-08-12-solo-project-owner-authority.md",
    "docs/superpowers/specs/2026-08-09-post-rc0-delivery-program-design.md",
    "docs/superpowers/specs/2026-08-09-v1-platform-scope-qualification-design.md",
    "docs/superpowers/specs/2026-08-12-solo-project-owner-authority-design.md",
))
exec((_parts_root / "pre_authority_overlay_repair.inc").read_text(encoding="utf-8"))
exec((_parts_root / "pre_authority_overlay_v2.inc").read_text(encoding="utf-8"))
exec((_parts_root / "pre_authority_overlay_v3.inc").read_text(encoding="utf-8"))
OVERLAY_V4_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V4.json"
_overlay_v4_part = _parts_root / "pre_authority_overlay_v4.inc"
_OVERLAY_V4_AVAILABLE = _overlay_v4_part.is_file()
if _OVERLAY_V4_AVAILABLE:
    exec(_overlay_v4_part.read_text(encoding="utf-8"))
OVERLAY_V5_ARTIFACT_PATH = "docs/authority/PRE_AUTHORITY_DOCUMENT_OVERLAY_V5.json"
_overlay_v5_part = _parts_root / "pre_authority_overlay_v5.inc"
_OVERLAY_V5_AVAILABLE = _overlay_v5_part.is_file()
if _OVERLAY_V5_AVAILABLE:
    exec(_overlay_v5_part.read_text(encoding="utf-8"))


def _mode(snapshot):
    pre, overlay, successor, v4, v5, composed = ARTIFACT_PATH in snapshot.entries, OVERLAY_ARTIFACT_PATH in snapshot.entries, OVERLAY_V3_ARTIFACT_PATH in snapshot.entries, OVERLAY_V4_ARTIFACT_PATH in snapshot.entries, OVERLAY_V5_ARTIFACT_PATH in snapshot.entries, COMPOSED_PATH in snapshot.entries
    if v5:
        if not _OVERLAY_V5_AVAILABLE:
            raise ValueError("OVERLAY_V5_IMPLEMENTATION_MISSING")
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v5"
    if v4:
        if not _OVERLAY_V4_AVAILABLE:
            raise ValueError("OVERLAY_V4_IMPLEMENTATION_MISSING")
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v4"
    if successor:
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v3"
    if sum((pre, overlay, composed)) > 1:
        raise ValueError("DOCS_MODE_CONFLICT")
    return "composed" if composed else "overlay" if overlay else "pre_authority" if pre else "legacy"


def _predecessor_mode(snapshot):
    paths = snapshot.head_paths()
    pre, overlay, successor, v4, v5, composed = ARTIFACT_PATH in paths, OVERLAY_ARTIFACT_PATH in paths, OVERLAY_V3_ARTIFACT_PATH in paths, OVERLAY_V4_ARTIFACT_PATH in paths, OVERLAY_V5_ARTIFACT_PATH in paths, COMPOSED_PATH in paths
    if v5:
        if not _OVERLAY_V5_AVAILABLE:
            raise ValueError("OVERLAY_V5_IMPLEMENTATION_MISSING")
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v5"
    if v4:
        if not _OVERLAY_V4_AVAILABLE:
            raise ValueError("OVERLAY_V4_IMPLEMENTATION_MISSING")
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v4"
    if successor:
        if pre or composed:
            raise ValueError("DOCS_MODE_CONFLICT")
        return "overlay_v3"
    if sum((pre, overlay, composed)) > 1:
        if is_exact_overlay_repair_predecessor(snapshot):
            return "repair"
        raise ValueError("DOCS_MODE_CONFLICT")
    return "composed" if composed else "overlay" if overlay else "pre_authority" if pre else "legacy"


def _select(snapshot):
    mode, previous = _mode(snapshot), _predecessor_mode(snapshot)
    if previous == "legacy" and mode == "overlay":
        raise ValueError("DOCS_MODE_TRANSITION")
    if previous == "overlay" and mode != "overlay":
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "pre_authority" and mode == "legacy":
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "repair" and mode != "overlay_v3":
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "overlay_v3" and mode not in {"overlay_v3", "overlay_v4"}:
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "overlay_v4" and mode not in {"overlay_v4", "overlay_v5"}:
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "overlay_v5" and mode != "overlay_v5":
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if previous == "composed" and mode != "composed":
        raise ValueError("DOCS_MODE_DOWNGRADE")
    if mode == "composed":
        validate_post_rc0_composed_authority(snapshot)
    return mode


def select_documentation_mode(repo: Path, *, index_file: Path | None = None) -> str:
    return _select(CandidateSnapshot.capture(repo, index_file=index_file))


def _immutable(snapshot):
    for path, expected in BASE_DIGESTS.items():
        entry = snapshot.entries.get(path)
        if entry is None or entry.mode != "100644" or digest(entry.blob_bytes) != expected:
            raise ValueError("DOCS_IMMUTABLE_MANIFEST_MUTATION")


def validate_immutable_rc0_manifests(repo: Path, *, index_file: Path | None = None) -> None:
    _immutable(CandidateSnapshot.capture(repo, index_file=index_file))


def _base_paths(snapshot):
    value = strict_json(snapshot.bytes("docs/rc0/document-universe-v1.json"), "DOCS_UNIVERSE_INVALID")
    paths = value.get("paths") if isinstance(value, dict) else None
    if not isinstance(paths, list):
        raise ValueError("DOCS_UNIVERSE_INVALID")
    result = set()
    for record in paths:
        path = record.get("path") if isinstance(record, dict) else None
        if not isinstance(path, str) or safe_path(path.encode()) in result:
            raise ValueError("DOCS_UNIVERSE_INVALID")
        result.add(path)
    return result


def _document_paths(snapshot, base):
    return {path for path, entry in snapshot.entries.items() if path.endswith((".md", ".markdown")) and path not in base and entry.mode == "100644"}


def _validate_retained_documents(snapshot, base, head):
    for path, (mode, _) in head.items():
        entry = snapshot.entries.get(path)
        if path.endswith((".md", ".markdown")) and path not in base and mode == "100644" and (entry is None or entry.mode != "100644"):
            raise ValueError("DOCS_DELTA_DELETION")


def _record_classification(path):
    return "governed" if path in GOVERNED_DELTA_PATHS else "non_governed"


def _validate_documents(snapshot, records, base):
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_ARTIFACT")
    paths = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != DOCUMENT_FIELDS:
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        path, state = record.get("path"), record.get("classification")
        if not isinstance(path, str) or safe_path(path.encode()) in paths or state != _record_classification(path):
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        entry = snapshot.entries.get(path)
        reason = record.get("reason")
        if entry is None or entry.mode != "100644" or path in base or record.get("sha256") != digest(entry.blob_bytes):
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        if (state == "governed" and reason is not None) or (state == "non_governed" and reason != "Outside the authoritative docs/ governance tree."):
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        paths.add(path)
    if paths != _document_paths(snapshot, base) or [record["path"] for record in records] != sorted(paths):
        raise ValueError("DOCS_DELTA_EXACTNESS")


def _validate_claims(snapshot, records, document_paths, *, frozen_protected=None):
    if not isinstance(records, list):
        raise ValueError("PRE_AUTHORITY_ARTIFACT")
    allowed = {"blocked_status": "BLOCKED", "design_policy": "NON_PRODUCTION", "terminology_reference": "NON_PRODUCTION", "out_of_scope_status": "OUT_OF_SCOPE"}
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != CLAIM_FIELDS:
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        path, kind = record.get("path"), record.get("claim_kind")
        key = (path, kind)
        if path not in document_paths or kind not in allowed or key in seen or record.get("disposition") != allowed[kind] or record.get("evidence_binding") != EVIDENCE_PROFILE:
            raise ValueError("PRE_AUTHORITY_ARTIFACT")
        seen.add(key)
    expected = _front_matter_claims(snapshot, document_paths)
    if seen != expected:
        raise ValueError("DOCS_STATUS_CLAIM_RECONCILIATION")
    if frozen_protected is not None and set(frozen_protected) - document_paths:
        raise ValueError("DOCS_AUTHORIZING_CLAIM")
    for path in document_paths:
        if protected_claim_diagnostics(snapshot.bytes(path)) != (frozen_protected or {}).get(path, []):
            raise ValueError("DOCS_AUTHORIZING_CLAIM")


def _front_matter_claims(snapshot, paths):
    allowed = {"blocked_status": "BLOCKED", "design_policy": "NON_PRODUCTION", "terminology_reference": "NON_PRODUCTION", "out_of_scope_status": "OUT_OF_SCOPE"}
    expected = set()
    for path in paths:
        if _record_classification(path) != "governed":
            continue
        fields = _claim_fields(snapshot.bytes(path))
        claims = [kind for kind in allowed if kind in fields]
        if "evidence_binding" in fields and fields["evidence_binding"] != EVIDENCE_PROFILE:
            raise ValueError("DOCS_STATUS_CLAIM_RECONCILIATION")
        for kind in claims:
            if fields[kind] != allowed[kind] or fields.get("evidence_binding") != EVIDENCE_PROFILE:
                raise ValueError("DOCS_STATUS_CLAIM_RECONCILIATION")
            expected.add((path, kind))
    return expected


def _claim_fields(raw):
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("DOCS_RESTRICTED_FRONT_MATTER") from error
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        return {}
    fields, end = {}, lines.index("---", 1)
    for line in lines[1:end]:
        match = re.fullmatch(r'([a-z_]+): "([^"\\]+)"', line)
        if match and match.group(1) in {"blocked_status", "design_policy", "terminology_reference", "out_of_scope_status", "evidence_binding"}:
            if match.group(1) in fields:
                raise ValueError("DOCS_RESTRICTED_FRONT_MATTER")
            fields[match.group(1)] = match.group(2)
    return fields


def _validate_pre(snapshot):
    schema, artifact = snapshot.entries.get(SCHEMA_PATH), snapshot.entries.get(ARTIFACT_PATH)
    if (schema is None or artifact is None or schema.stage != "0" or artifact.stage != "0"
            or schema.mode != "100644" or artifact.mode != "100644" or digest(schema.blob_bytes) != SCHEMA_SHA256):
        raise ValueError("PRE_AUTHORITY_SCHEMA_PIN")
    value = strict_json(artifact.blob_bytes, "PRE_AUTHORITY_ARTIFACT")
    if not isinstance(value, dict) or set(value) != ARTIFACT_FIELDS or value.get("schema_version") != 1 or value.get("mode") != "pre_authority" or not isinstance(value.get("repository_id"), str) or not value["repository_id"]:
        raise ValueError("PRE_AUTHORITY_ARTIFACT")
    for field, path in zip(("base_universe_bytes_sha256", "base_governed_scope_bytes_sha256", "base_status_claims_bytes_sha256"), BASE_DIGESTS):
        if value.get(field) != BASE_DIGESTS[path]:
            raise ValueError("PRE_AUTHORITY_BASE_DIGEST")
    base = _base_paths(snapshot)
    head = snapshot.head_entries()
    present_base = base & set(head)
    if any(path not in snapshot.entries or ((snapshot.entries[path].mode, snapshot.entries[path].oid) != head[path]
            and (snapshot.entries[path].mode != "100644" or TASK1_BASE_DOCUMENT_OVERRIDE.get(path) != digest(snapshot.entries[path].blob_bytes))) for path in present_base):
        raise ValueError("DOCS_BASE_MUTATION")
    if any(path.endswith((".md", ".markdown")) and path not in base and entry.mode != "100644" for path, entry in snapshot.entries.items()):
        raise ValueError("DOCS_DELTA_ENTRY_INVALID")
    _validate_retained_documents(snapshot, base, head)
    _validate_documents(snapshot, value["documents"], base)
    _validate_claims(snapshot, value["status_claims"], _document_paths(snapshot, base))


def validate_pre_authority_document_delta(repo: Path, *, index_file: Path | None = None) -> None:
    snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
    _immutable(snapshot)
    if _select(snapshot) == "pre_authority":
        _validate_pre(snapshot)


def validate_documentation_mode(repo: Path, *, index_file: Path | None = None) -> list[str]:
    try:
        snapshot = CandidateSnapshot.capture(repo, index_file=index_file)
        _immutable(snapshot)
        mode = _select(snapshot)
        if mode == "legacy":
            return validate_legacy_snapshot(snapshot) if "validate_document_universe" in globals() else []
        if mode == "overlay":
            _validate_pre_authority_document_overlay_v2(snapshot)
        elif mode == "overlay_v3":
            _validate_pre_authority_document_overlay_v3(snapshot)
        elif mode == "overlay_v4":
            _validate_pre_authority_document_overlay_v4(snapshot)
        elif mode == "overlay_v5":
            _validate_pre_authority_document_overlay_v5(snapshot)
        else:
            _validate_pre(snapshot)
        return []
    except ValueError as error:
        return [str(error)]
