"""Canonical bytes for the closed Task 12 human fixture contract."""

from scripts.release_v2.canonical import canonical_json


def canonical_human_artifacts(
    candidate_sha256: str, version: str, source_sha256: str
) -> dict[str, bytes]:
    """Return the exact inert human artifacts for manifest-bound fixture values."""
    binding = {
        "candidate_sha256": candidate_sha256,
        "fixture_class": "STRUCTURAL_FIXTURE_ONLY",
        "production_evidence": "PROHIBITED",
        "release_date": "2023-11-14",
        "schema_version": "human-fixture-binding.v1",
        "source_sha256": source_sha256,
        "verifier": "fixture-verifier-v1",
        "version": version,
    }
    header = "\n".join((
        "STRUCTURAL_FIXTURE_ONLY",
        f"candidate_sha256: {candidate_sha256}",
        f"version: {version}",
        "release_date: 2023-11-14",
        f"source_sha256: {source_sha256}",
        "PATHS: RELATIVE_ONLY",
        "CREDENTIALS: OMITTED",
        "PRODUCTION_EVIDENCE: PROHIBITED",
        "LIMITATION: BLOCKED_EVIDENCE",
        "VERIFICATION_INSTRUCTIONS:",
        "- Compare binding fields with human/binding.v1.json and manifest.v2.json.",
        "- Confirm the fixture result remains blocked and structural only.",
    ))
    documents = {
        "changelog.md": f"# Fixture changelog\n\n{header}\n",
        "release-notes.md": f"# Fixture release notes\n\n{header}\n",
        "rollback.md": f"# Fixture rollback\n\n{header}\nROLLBACK_COMPATIBILITY_PREFLIGHT: NOT_RUN\n",
        "pr-description.md": f"# Fixture PR description\n\n{header}\nPR_REQUIRED_GATE: source-candidate-binding=REQUIRED_NOT_RUN\nPR_REQUIRED_GATE: qualification-evidence=REQUIRED_NOT_RUN\n",
        "merge-checklist.md": f"# Fixture merge checklist\n\n{header}\nMERGE_REQUIRED_GATE: source-candidate-binding=REQUIRED_NOT_RUN\nMERGE_REQUIRED_GATE: qualification-evidence=REQUIRED_NOT_RUN\n",
    }
    values = {"human/binding.v1.json": canonical_json(binding)}
    values.update({f"human/{name}": value.encode("utf-8") for name, value in documents.items()})
    return values
