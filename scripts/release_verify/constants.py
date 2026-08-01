from __future__ import annotations

GATE_ORDER = [
    "source-integrity", "source-clean", "profile-integrity", "manifest", "qualification-state", "checksums", "artifact-digest",
    "hosted-platform-evidence", "security-evidence", "performance-evidence", "compatibility",
    "install-upgrade-rollback",
    "phase6b-native-certificate", "phase8-compatibility", "phase9-operations",
    "independent-final-review", "owner-approval", "approval-attestation",
]
ALLOWED_EVIDENCE_KINDS = {
    "package", "checksums", "provenance-attestation", "sbom",
    "hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs",
    "advisory", "license", "secret-scan", "performance", "soak", "chaos",
    "fresh-install", "upgrade", "rollback", "compatibility",
    "phase6b-native-certificate", "phase8-compatibility", "phase9-operations",
    "review-packet", "independent-final-review", "owner-approval", "blocked-gate",
}
SUPPLY_CHAIN_GATE_IDS = {
    "advisory": "advisory",
    "license": "license",
    "secret-scan": "secret-scan",
    "sbom": "sbom",
    "performance": "performance",
    "soak": "soak",
    "chaos": "chaos",
}
OPERATION_KINDS = {"fresh-install", "upgrade", "rollback"}
RELEASE_OPERATION_SCHEMA_REVISION = "release-operation-evidence.v1"
PHASE_EVIDENCE_SCHEMAS = {
    "phase6b-native-certificate": "phase6b-native-certificate.v1",
    "phase8-compatibility": "phase8-compatibility-evidence.v1",
    "phase9-operations": "phase9-operations-evidence.v1",
}
EXPECTED_LANES = {
    "pinned-1.97.1": "1.97.1",
    "msrv-1.95.0": "1.95.0",
}
HOSTED_KINDS = {"hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs"}
