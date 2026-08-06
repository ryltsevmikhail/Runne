"""Validation for inert Task 12 human fixture artifacts only."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.canonical import parse_canonical_json
from scripts.release_v2.human_fixture_commands import contains_production_command
from scripts.release_v2.human_fixture_contract import canonical_human_artifacts
from scripts.release_v2.inventory import TreeBytes, capture_tree_bytes, parse_checksums
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


_HUMAN_FILES = (
    "human/binding.v1.json", "human/changelog.md", "human/release-notes.md",
    "human/rollback.md", "human/pr-description.md", "human/merge-checklist.md",
)
_FIXTURE_FILES = (
    "advisory-report.v1.json", "archive-index.v1.json", "archive.tar",
    "artifact-inventory.v2.json", "build-input.v2.json", "checksums.sha256",
    "claim-matrix.v1.json", "dependency-inventory.v1.json", "fixture-result.v1.json",
    "fixture-inputs.v1.json",
    "license-report.v1.json", "manifest.v2.json", "product-tuple.v1.json",
    "provenance.v1.json", "qualification-evidence.v1.json",
    "qualification-subject.v1.json", "release-snapshot.v1.json", "sbom.cdx.json",
)
_CONTENT_FILES = _FIXTURE_FILES + _HUMAN_FILES
_SIDECAR_FILES = tuple(f"{name}.sha256" for name in _CONTENT_FILES)
_ALLOWED_FILES = frozenset(_CONTENT_FILES + _SIDECAR_FILES)
_ALLOWED_DIRECTORIES = frozenset(("human",))
_BINDING_KEYS = frozenset((
    "candidate_sha256", "fixture_class", "production_evidence", "release_date",
    "schema_version", "source_sha256", "verifier", "version",
))
_UNSAFE_MARKER = re.compile(r"/Users/|/home/|[A-Za-z]:\\|AKIA|ghp_|github_pat_|gh[opusr]_|glpat-|xox[baprs]-|ASIA[0-9A-Z]{16}|-----BEGIN[ A-Z]*PRIVATE KEY-----|eyJ[\w-]+\.[\w-]+\.[\w-]+|Bearer\s|\\\\|/var/folders/|sk-(?:ant-)?[\w-]{16,}|token=|password=|private_key", re.IGNORECASE)
_INVENTORY_FIELDS = frozenset(("schema_version", "candidate_sha256", "entries", "inventory_sha256"))
_ENTRY_FIELDS = frozenset(("path", "kind", "mode", "size", "sha256"))


@dataclass(frozen=True)
class HumanFixtureResult:
    fixture_class: str
    production_approved: bool


def snapshot_human_fixture(root: Path) -> TreeBytes:
    """Return the complete supplied fixture byte snapshot without writing it."""
    return capture_tree_bytes(root)


def validate_human_fixture(root: Path, *, before: TreeBytes | None = None) -> HumanFixtureResult:
    """Validate one generated structural fixture; never produce a production claim."""
    initial = snapshot_human_fixture(root) if before is None else before
    current = snapshot_human_fixture(root)
    if type(initial) is not TreeBytes or current != initial:
        _fail(FailureCodeV1.INPUT_MUTATION_DETECTED, "fixture input changed")
    error: ReleaseFailure | None = None
    try:
        _validate_tree(current)
        _validate_sidecars(current)
        parse_checksums(current.bytes_for("checksums.sha256"), _inventory(current.bytes_for("artifact-inventory.v2.json")))
        binding = _load_json(current.bytes_for("human/binding.v1.json"))
        manifest = _load_json(current.bytes_for("manifest.v2.json"))
        build = _load_json(current.bytes_for("build-input.v2.json"))
        _validate_binding(binding, manifest, build)
        expected = canonical_human_artifacts(
            binding["candidate_sha256"], binding["version"], binding["source_sha256"]
        )
        _validate_documents(current, binding, expected)
        _validate_human_bytes(current, expected)
    except ReleaseFailure as caught:
        error = caught
    try:
        unchanged = snapshot_human_fixture(root) == current
    except ReleaseFailure:
        unchanged = False
    if not unchanged:
        _fail(FailureCodeV1.INPUT_MUTATION_DETECTED, "fixture input changed")
    if error is not None:
        raise error
    return HumanFixtureResult("STRUCTURAL_FIXTURE_ONLY", False)


def _validate_binding(binding: object, manifest: object, build: object) -> None:
    if type(binding) is not dict or frozenset(binding) != _BINDING_KEYS:
        _fail(FailureCodeV1.MANIFEST_INVALID, "binding metadata invalid")
    if type(manifest) is not dict or type(build) is not dict:
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture metadata invalid")
    if any(type(value) is not str for value in (
        manifest.get("candidate_sha256"), build.get("source_tree_sha256"),
        build.get("release_version"),
    )):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture metadata invalid")
    expected = {
        "schema_version": "human-fixture-binding.v1",
        "fixture_class": "STRUCTURAL_FIXTURE_ONLY",
        "production_evidence": "PROHIBITED",
        "verifier": "fixture-verifier-v1",
        "release_date": "2023-11-14",
        "candidate_sha256": manifest.get("candidate_sha256"),
        "source_sha256": build.get("source_tree_sha256"),
        "version": build.get("release_version"),
    }
    if binding != expected:
        _fail(FailureCodeV1.CANDIDATE_IDENTITY_MISMATCH, "fixture binding mismatch")


def _validate_tree(tree: TreeBytes) -> None:
    files = {entry.path: entry for entry in tree.entries if entry.kind == "file"}
    directories = {entry.path: entry for entry in tree.entries if entry.kind == "directory"}
    if set(files) != _ALLOWED_FILES or set(directories) != _ALLOWED_DIRECTORIES:
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture file set invalid")
    if any(entry.mode != "0644" for entry in files.values()) or any(entry.mode != "0755" for entry in directories.values()):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture file set invalid")


def _validate_sidecars(tree: TreeBytes) -> None:
    bindings: dict[str, str] = {}
    for sidecar in _SIDECAR_FILES:
        try:
            digest, path = _sidecar_row(tree.bytes_for(sidecar))
        except (KeyError, ReleaseFailure):
            _fail(FailureCodeV1.MANIFEST_INVALID, "fixture sidecar invalid")
        content = sidecar.removesuffix(".sha256")
        if path != content or content in bindings:
            _fail(FailureCodeV1.MANIFEST_INVALID, "fixture sidecar invalid")
        bindings[content] = digest
    if frozenset(bindings) != frozenset(_CONTENT_FILES):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture sidecar invalid")
    for content, digest in bindings.items():
        if hashlib.sha256(tree.bytes_for(content)).hexdigest() != digest:
            _fail(FailureCodeV1.ARTIFACT_DIGEST_MISMATCH, "fixture digest mismatch")


def _validate_documents(
    tree: TreeBytes, binding: dict[str, object], expected: dict[str, bytes]
) -> None:
    documents = {
        name: _text(tree.bytes_for(name)) for name in _HUMAN_FILES if name != "human/binding.v1.json"
    }
    required = (
        "STRUCTURAL_FIXTURE_ONLY", "PATHS: RELATIVE_ONLY", "CREDENTIALS: OMITTED",
        "PRODUCTION_EVIDENCE: PROHIBITED", "LIMITATION: BLOCKED_EVIDENCE",
        "VERIFICATION_INSTRUCTIONS:",
    ) + tuple(f"{name}: {binding[name]}" for name in ("candidate_sha256", "version", "release_date", "source_sha256"))
    if any(_UNSAFE_MARKER.search(text) for text in documents.values()):
        _fail(FailureCodeV1.PATH_UNSAFE, "unsafe fixture marker")
    if any(contains_production_command(_text(raw)) for raw in expected.values()):
        _fail(FailureCodeV1.MANIFEST_INVALID, "production command forbidden")
    if any(marker not in text for text in documents.values() for marker in required):
        _fail(FailureCodeV1.CANDIDATE_IDENTITY_MISMATCH, "document binding mismatch")
    rollback = documents["human/rollback.md"]
    if "ROLLBACK_COMPATIBILITY_PREFLIGHT: NOT_RUN" not in rollback:
        _fail(FailureCodeV1.ROLLBACK_UNSUPPORTED, "rollback is unsupported")
    gates = (
        ("human/pr-description.md", "PR_REQUIRED_GATE"),
        ("human/merge-checklist.md", "MERGE_REQUIRED_GATE"),
    )
    for name, gate in gates:
        text = documents[name]
        for check in ("source-candidate-binding", "qualification-evidence"):
            if f"{gate}: {check}=REQUIRED_NOT_RUN" not in text:
                _fail(FailureCodeV1.MANIFEST_INVALID, "required gate invalid")


def _validate_human_bytes(tree: TreeBytes, expected: dict[str, bytes]) -> None:
    if tuple(expected) != _HUMAN_FILES or any(
        tree.bytes_for(name) != raw for name, raw in expected.items()
    ) or any(
        tree.bytes_for(f"{name}.sha256")
        != f"{hashlib.sha256(raw).hexdigest()}  {name}\n".encode("utf-8")
        for name, raw in expected.items()
    ):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture human artifact invalid")


def _inventory(raw: bytes) -> ArtifactInventoryV2:
    try:
        document = parse_canonical_json(raw, required=_INVENTORY_FIELDS, optional=frozenset())
        rows = document["entries"]
        if type(rows) is not list:
            raise ValueError
        entries = tuple(_entry(row) for row in rows)
        return ArtifactInventoryV2(document["schema_version"], document["candidate_sha256"], entries, document["inventory_sha256"])
    except (ReleaseFailure, TypeError, ValueError):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture json invalid")


def _entry(value: object) -> ArtifactEntry:
    if type(value) is not dict or frozenset(value) != _ENTRY_FIELDS or type(value["path"]) is not str or type(value["kind"]) is not str or type(value["mode"]) is not str or type(value["size"]) is not int or type(value["sha256"]) is not str:
        raise ValueError
    return ArtifactEntry(value["path"], value["kind"], value["mode"], value["size"], value["sha256"])


def _sidecar_row(raw: bytes) -> tuple[str, str]:
    try:
        row = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_sidecar_invalid") from error
    if not row.endswith("\n") or row.count("\n") != 1 or len(row) < 68 or row[64:66] != "  ":
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_sidecar_invalid")
    digest, path = row[:64], row[66:-1]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest) or not path or "\\" in path or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_sidecar_invalid")
    return digest, path


def _load_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture json invalid")


def _text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail(FailureCodeV1.MANIFEST_INVALID, "fixture text invalid")


def _fail(code: FailureCodeV1, detail: str) -> None:
    raise ReleaseFailure(code, detail)
