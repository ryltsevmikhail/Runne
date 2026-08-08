"""Closed-set taxonomy, Markdown inventory, and status-claim validation."""
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import unicodedata


REPOSITORY_ROOT = Path(globals().get("BASE", Path(__file__).resolve().parents[2]))
PARTS_DIR = REPOSITORY_ROOT / "scripts" / "validate_docs_parts"
MIGRATION_PATH = REPOSITORY_ROOT / "docs" / "rc0" / "taxonomy-migration-v1.json"
MIGRATION = json.loads(MIGRATION_PATH.read_text(encoding="utf-8"))
RELEASE_PREFIXES = ("docs/release/", "docs/desktop/09-release/", "docs/desktop/03-desktop/")
CLAIM_PATTERNS = (
    ("RC0_QUALIFIED", re.compile(r"rc0qualified")),
    ("CANDIDATE_PASS", re.compile(r"candidatepass")),
    ("PRODUCTION_QUALIFICATION", re.compile(r"productionqualificationpass")),
    ("RELEASE_PASS", re.compile(r"releasepass")),
    ("SIGNING_PASS", re.compile(r"signingpass")),
    ("NOTARIZATION_PASS", re.compile(r"notarizationpass")),
    ("PUBLICATION_PASS", re.compile(r"publicationpass")),
)
REQUIRED_CLAIM = {
    "claim_id": "RC0-CANDIDATE-NON-PRODUCTION",
    "path": "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
    "subject": "RC0-candidate",
    "claim_kind": "design_policy",
    "disposition": "NON_PRODUCTION",
    "evidence_binding": "gocode.rc0.evidence-profile/3",
}


@dataclass(frozen=True)
class ClaimRecord:
    claim_id: str
    path: str
    subject: str
    claim_kind: str
    disposition: str
    evidence_binding: str


def tracked_markdown_paths(root: Path) -> tuple[str, ...]:
    """Return tracked Markdown paths, rejecting malformed Git output fail-closed."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ValueError("UNIVERSE_GIT_LS_FILES")
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            path = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("UNIVERSE_INVALID_UTF8_PATH") from None
        if raw.rsplit(b"/", 1)[-1].endswith((b".md", b".markdown")):
            paths.append(path)
    return tuple(sorted(paths))


def validate_taxonomy_fields(fields: dict[str, str]) -> list[str]:
    """Validate only exact ADR-0025 legacy values before canonical migration."""
    diagnostics = []
    for field in ("status", "document_type", "source_status"):
        if field in fields and fields[field] not in MIGRATION[field]:
            diagnostics.append(f"TAXONOMY_UNMAPPED_{field.upper()}:{fields[field]}")
    return diagnostics


def _read_json(path: Path, code: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(code) from None


def _read_manifests(root: Path):
    rc0 = root / "docs" / "rc0"
    names = ("document-universe-v1.json", "governed-scope-v1.json", "status-claims-v1.json")
    paths = [rc0 / name for name in names]
    if not all(path.is_file() for path in paths):
        raise ValueError("UNIVERSE_MANIFEST_MISSING")
    return tuple(_read_json(path, "UNIVERSE_MANIFEST_INVALID") for path in paths)


def _records(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("paths"), list):
        raise ValueError("UNIVERSE_MANIFEST_INVALID")
    records = raw["paths"]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("UNIVERSE_MANIFEST_INVALID")
    return records


def _scope_paths(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("paths"), list):
        raise ValueError("UNIVERSE_MANIFEST_INVALID")
    if not all(isinstance(path, str) for path in raw["paths"]):
        raise ValueError("UNIVERSE_MANIFEST_INVALID")
    return raw["paths"]


def _compact_claim_text(text: str) -> str:
    return re.sub(r"[\s_-]+", "", unicodedata.normalize("NFKC", text).casefold())


def validate_status_claims(
    universe: tuple[str, ...], scope: frozenset[str], claims: tuple[ClaimRecord, ...]
) -> list[str]:
    """Reject records that are not exact, in-scope members of the universe."""
    diagnostics, seen = [], set()
    required = {"claim_id", "path", "subject", "claim_kind", "disposition", "evidence_binding"}
    for claim in claims:
        key = tuple(getattr(claim, field) for field in required)
        if key in seen:
            diagnostics.append(f"CLAIM_DUPLICATE:{claim.claim_id}")
        seen.add(key)
        if claim.path not in universe:
            diagnostics.append(f"CLAIM_PATH_OUTSIDE_UNIVERSE:{claim.path}")
        elif claim.path not in scope:
            diagnostics.append(f"CLAIM_PATH_NOT_GOVERNED:{claim.path}")
        if not all(isinstance(getattr(claim, field), str) and getattr(claim, field) for field in required):
            diagnostics.append(f"CLAIM_INVALID:{claim.claim_id}")
    return sorted(set(diagnostics))


def _claim_records(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("claims"), list):
        raise ValueError("CLAIM_MANIFEST_INVALID")
    fields = {"claim_id", "path", "subject", "claim_kind", "disposition", "evidence_binding"}
    claims = []
    for item in raw["claims"]:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("CLAIM_MANIFEST_INVALID")
        claims.append(ClaimRecord(**item))
    return tuple(claims)


def validate_document_universe(root: Path) -> list[str]:
    """Return stable diagnostics; an empty list is the only success result."""
    try:
        inventory_raw, scope_raw, claims_raw = _read_manifests(root)
        universe = tracked_markdown_paths(root)
        records = _records(inventory_raw)
        scope_records = _scope_paths(scope_raw)
        claims = _claim_records(claims_raw)
    except ValueError as error:
        return [str(error)]
    diagnostics, classifications, reasons = [], {}, {}
    for record in records:
        path, classification = record.get("path"), record.get("classification")
        if not isinstance(path, str) or classification not in {"governed", "non_governed"}:
            diagnostics.append("UNIVERSE_MANIFEST_INVALID")
            continue
        if path in classifications:
            diagnostics.append(f"UNIVERSE_DUPLICATE_PATH:{path}")
        classifications[path] = classification
        reasons[path] = record.get("reason")
        if classification == "non_governed" and not isinstance(reasons[path], str):
            diagnostics.append(f"UNIVERSE_EXCLUSION_REASON:{path}")
    manifest_paths, actual_paths = set(classifications), set(universe)
    diagnostics.extend(f"UNIVERSE_EXTRA_PATH:{path}" for path in sorted(manifest_paths - actual_paths))
    diagnostics.extend(f"UNIVERSE_OMITTED_PATH:{path}" for path in sorted(actual_paths - manifest_paths))
    for path in sorted(actual_paths & manifest_paths):
        if classifications[path] == "non_governed" and not reasons[path].strip():
            diagnostics.append(f"UNIVERSE_EXCLUSION_REASON:{path}")
    governed = frozenset(path for path, state in classifications.items() if state == "governed")
    scope = set(scope_records)
    if len(scope) != len(scope_records):
        diagnostics.append("SCOPE_DUPLICATE_PATH")
    diagnostics.extend(f"SCOPE_EXTRA_PATH:{path}" for path in sorted(scope - governed))
    diagnostics.extend(f"SCOPE_OMITTED_PATH:{path}" for path in sorted(governed - scope))
    for prefix in RELEASE_PREFIXES:
        for path in sorted(actual_paths):
            if path.startswith(prefix) and classifications.get(path) == "non_governed" and not str(reasons[path]).strip():
                diagnostics.append(f"UNIVERSE_EXCLUSION_REASON:{path}")
    diagnostics.extend(validate_status_claims(universe, frozenset(scope), claims))
    if REQUIRED_CLAIM not in [claim.__dict__ for claim in claims]:
        diagnostics.append("CLAIM_REQUIRED_MISSING:RC0-CANDIDATE-NON-PRODUCTION")
    allowed = {(claim.path, claim.claim_id) for claim in claims}
    for path in universe:
        try:
            content = (root / path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            diagnostics.append(f"CLAIM_INVALID_UTF8:{path}")
            continue
        compact = _compact_claim_text(content)
        for claim_id, pattern in CLAIM_PATTERNS:
            if pattern.search(compact) and (path, claim_id) not in allowed:
                diagnostics.append(f"CLAIM_UNLISTED:{path}:{claim_id}")
    return sorted(set(diagnostics))
