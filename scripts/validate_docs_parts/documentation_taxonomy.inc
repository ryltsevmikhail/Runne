"""Closed-set taxonomy, Markdown inventory, and status-claim validation."""
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


REPOSITORY_ROOT = Path(globals().get("BASE", Path(__file__).resolve().parents[2]))
PARTS_DIR = REPOSITORY_ROOT / "scripts" / "validate_docs_parts"
MIGRATION_PATH = REPOSITORY_ROOT / "docs" / "rc0" / "taxonomy-migration-v1.json"
MIGRATION = json.loads(MIGRATION_PATH.read_text(encoding="utf-8"))
FRONT_MATTER_SPEC = importlib.util.spec_from_file_location(
    "gocode_restricted_front_matter", PARTS_DIR / "front_matter.py"
)
FRONT_MATTER = importlib.util.module_from_spec(FRONT_MATTER_SPEC)
FRONT_MATTER_SPEC.loader.exec_module(FRONT_MATTER)
CLAIM_SPEC = importlib.util.spec_from_file_location(
    "gocode_claim_outcomes", PARTS_DIR / "claim_outcomes.py"
)
CLAIM_OUTCOMES = importlib.util.module_from_spec(CLAIM_SPEC)
CLAIM_SPEC.loader.exec_module(CLAIM_OUTCOMES)
RELEASE_PREFIXES = ("docs/release/", "docs/desktop/09-release/", "docs/desktop/03-desktop/")
EVIDENCE_PROFILE = "gocode.rc0.evidence-profile/3"
CLAIM_SEMANTICS = {
    "blocked_status": ("BLOCKED", EVIDENCE_PROFILE),
    "design_policy": ("NON_PRODUCTION", EVIDENCE_PROFILE),
    "out_of_scope_status": ("OUT_OF_SCOPE", EVIDENCE_PROFILE),
    "terminology_reference": ("NON_PRODUCTION", EVIDENCE_PROFILE),
}
REQUIRED_CLAIM = {
    "claim_id": "RC0-CANDIDATE-NON-PRODUCTION",
    "path": "docs/superpowers/specs/2026-08-08-rc0-candidate-design.md",
    "subject": "RC0-candidate",
    "claim_kind": "design_policy",
    "disposition": "NON_PRODUCTION",
    "evidence_binding": EVIDENCE_PROFILE,
}


@dataclass(frozen=True)
class ClaimRecord:
    claim_id: str
    path: str
    subject: str
    claim_kind: str
    disposition: str
    evidence_binding: str


def _claim_strings_valid(claim: ClaimRecord) -> bool:
    return all(isinstance(value, str) and value for value in (
        claim.claim_id, claim.path, claim.subject, claim.claim_kind,
        claim.disposition, claim.evidence_binding,
    ))


def _claim_semantics_valid(claim: ClaimRecord) -> bool:
    return (_claim_strings_valid(claim)
            and CLAIM_SEMANTICS.get(claim.claim_kind)
            == (claim.disposition, claim.evidence_binding))


def tracked_markdown_paths(root: Path, *, index_file: Path | None = None) -> tuple[str, ...]:
    """Return tracked Markdown paths, rejecting malformed Git output fail-closed."""
    env = None if index_file is None else {**os.environ, "GIT_INDEX_FILE": str(index_file)}
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env,
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


def _parse_governed_front_matter(raw: bytes) -> dict[str, str]:
    """Apply restricted parsing with exact ADR-0025 legacy scalar migration."""
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return FRONT_MATTER.parse_restricted_front_matter(raw)
    if lines and lines[0] == "---":
        try:
            end = lines.index("---", 1)
            lines = lines[:end + 1]
            raw = ("\n".join(lines) + "\n").encode()
        except ValueError:
            pass
    try:
        return FRONT_MATTER.parse_restricted_front_matter(raw)
    except ValueError as error:
        if str(error) != "FM_UNQUOTED_STRING":
            raise
        original_error = error
    if not lines or lines[0] != "---":
        raise original_error
    end = lines.index("---", 1)
    for index in range(1, end):
        match = re.fullmatch(r"(status|document_type|source_status): ([^\"']\S*)", lines[index])
        if match and match.group(2) in MIGRATION[match.group(1)]:
            lines[index] = f'{match.group(1)}: {json.dumps(match.group(2))}'
    return FRONT_MATTER.parse_restricted_front_matter(("\n".join(lines) + "\n").encode())


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


def validate_status_claims(
    universe: tuple[str, ...], scope: frozenset[str], claims: tuple[ClaimRecord, ...]
) -> list[str]:
    """Reject records that are not exact, in-scope members of the universe."""
    diagnostics, seen = [], set()
    for claim in claims:
        if not _claim_strings_valid(claim):
            diagnostics.append("CLAIM_INVALID:INVALID")
            continue
        key = (claim.path, claim.claim_id)
        if key in seen:
            diagnostics.append(f"CLAIM_DUPLICATE:{claim.path}:{claim.claim_id}")
        seen.add(key)
        if claim.path not in universe:
            diagnostics.append(f"CLAIM_PATH_OUTSIDE_UNIVERSE:{claim.path}")
        elif claim.path not in scope:
            diagnostics.append(f"CLAIM_PATH_NOT_GOVERNED:{claim.path}")
        if not _claim_semantics_valid(claim):
            diagnostics.append(f"CLAIM_SEMANTICS_INVALID:{claim.path}:{claim.claim_id}")
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


def validate_document_universe(root: Path, *, index_file: Path | None = None) -> list[str]:
    """Return stable diagnostics; an empty list is the only success result."""
    try:
        inventory_raw, scope_raw, claims_raw = _read_manifests(root)
        universe = tracked_markdown_paths(root, index_file=index_file)
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
        reason = reasons[path]
        if classifications[path] == "non_governed" and (
            not isinstance(reason, str) or not reason.strip()
        ):
            diagnostics.append(f"UNIVERSE_EXCLUSION_REASON:{path}")
    governed = frozenset(path for path, state in classifications.items() if state == "governed")
    scope = set(scope_records)
    if len(scope) != len(scope_records):
        diagnostics.append("SCOPE_DUPLICATE_PATH")
    diagnostics.extend(f"SCOPE_EXTRA_PATH:{path}" for path in sorted(scope - governed))
    diagnostics.extend(f"SCOPE_OMITTED_PATH:{path}" for path in sorted(governed - scope))
    for prefix in RELEASE_PREFIXES:
        for path in sorted(actual_paths):
            reason = reasons.get(path)
            if (path.startswith(prefix) and classifications.get(path) == "non_governed"
                    and (not isinstance(reason, str) or not reason.strip())):
                diagnostics.append(f"UNIVERSE_EXCLUSION_REASON:{path}")
    diagnostics.extend(validate_status_claims(universe, frozenset(scope), claims))
    if REQUIRED_CLAIM not in [claim.__dict__ for claim in claims]:
        diagnostics.append("CLAIM_REQUIRED_MISSING:RC0-CANDIDATE-NON-PRODUCTION")
    allowed = {
        (claim.path, claim.claim_id) for claim in claims
        if _claim_semantics_valid(claim)
    }
    detected = set()
    for path in universe:
        try:
            raw = (root / path).read_bytes()
        except OSError:
            diagnostics.append(f"DOCUMENT_FRONT_MATTER:{path}:FM_READ_ERROR")
            continue
        if classifications.get(path) == "governed":
            try:
                fields = _parse_governed_front_matter(raw)
                for diagnostic in validate_taxonomy_fields(fields):
                    diagnostics.append(f"DOCUMENT_TAXONOMY:{path}:{diagnostic}")
            except ValueError as error:
                diagnostics.append(f"DOCUMENT_FRONT_MATTER:{path}:{error}")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            diagnostics.append(f"DOCUMENT_FRONT_MATTER:{path}:FM_INVALID_UTF8")
            continue
        try:
            parsed = CLAIM_OUTCOMES.parse_claims(content)
        except CLAIM_OUTCOMES.ClaimParseError as error:
            diagnostics.append(f"CLAIM_PARSE:{path}:{error}")
            continue
        for claim_id in parsed.mentions:
            detected.add((path, claim_id))
            if (path, claim_id) not in allowed:
                diagnostics.append(f"CLAIM_UNLISTED:{path}:{claim_id}")
        diagnostics.extend(
            f"CLAIM_POSITIVE_OUTCOME:{path}:{claim_id}"
            for claim_id in parsed.positive_outcomes
        )
    required_key = (REQUIRED_CLAIM["path"], REQUIRED_CLAIM["claim_id"])
    diagnostics.extend(
        f"CLAIM_RECORD_UNMATCHED:{path}:{claim_id}"
        for path, claim_id in sorted(allowed - detected - {required_key})
    )
    return sorted(set(diagnostics))
