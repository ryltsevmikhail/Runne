"""V3 successor-trust schema closure before promotion pin finalization."""

import json
import hashlib
import re
import unittest
from pathlib import Path

from scripts.project_owner_authority.schema_semantics import trust_v3_errors
from scripts.tests.test_project_owner_authority_schemas import ROOT, _errors


SOURCES = {
    "gocode.governance.v1-platform-scope-decision/1": "v1-platform-scope-decision-v1.schema.json",
    "gocode.project-owner.authority-receipt/2": "project-owner-authority-receipt-v2.schema.json",
    "gocode.project-owner.authority-receipt/3": "project-owner-authority-receipt-v3.schema.json",
    "gocode.project-owner.authority-receipt/4": "project-owner-authority-receipt-v4.schema.json",
    "gocode.rc0.post-rc0-platform-composed-universe/1": "post-rc0-platform-composed-universe-v1.schema.json",
    "gocode.release.post-rc0-stage-envelope/1": "release-post-rc0-stage-envelope-v1.schema.json",
    "gocode.release.promotion-state-snapshot/1": "promotion-state-snapshot-v1.schema.json",
    "gocode.release.publication-manifest/1": "publication-manifest-v1.schema.json",
    "gocode.release.rc1-qualification-decision/1": "release-rc1-qualification-decision-v1.schema.json",
    "gocode.release.rc2-signed-artifact-record/1": "release-rc2-signed-artifact-record-v1.schema.json",
    "gocode.release.rc2-signing-authorization/1": "rc2-signing-authorization-v1.schema.json",
    "gocode.release.rc2-threshold-update-metadata-set/1": "release-rc2-threshold-update-metadata-set-v1.schema.json",
    "gocode.release.rc3-publication-authorization/1": "rc3-publication-authorization-v1.schema.json",
    "gocode.release.signed-envelope-inventory/1": "signed-envelope-inventory-v1.schema.json",
    "gocode.release.signed-envelope-verification-report/1": "signed-envelope-verification-report-v1.schema.json",
    "gocode.release.unsigned-candidate-manifest/1": "unsigned-candidate-manifest-v1.schema.json",
    "gocode.v1-platform-scope-claim-migration/1": "v1-platform-scope-claim-migration-v1.schema.json",
}


def config() -> dict:
    return {
        "schema_version": "gocode.project-owner.trust-config/3",
        "repository_id": "gocode", "role": "PROJECT_OWNER", "epoch": 3,
        "key_id": "a" * 64, "public_key": "A" * 43,
        "schema_digests": [{"schema_id": schema_id, "schema_sha256": "b" * 64} for schema_id in [
            "gocode.governance.v1-platform-scope-decision/1", "gocode.project-owner.authority-receipt/2", "gocode.project-owner.authority-receipt/3", "gocode.project-owner.authority-receipt/4", "gocode.rc0.post-rc0-platform-composed-universe/1", "gocode.release.post-rc0-stage-envelope/1", "gocode.release.promotion-state-snapshot/1", "gocode.release.publication-manifest/1", "gocode.release.rc1-qualification-decision/1", "gocode.release.rc2-signed-artifact-record/1", "gocode.release.rc2-signing-authorization/1", "gocode.release.rc2-threshold-update-metadata-set/1", "gocode.release.rc3-publication-authorization/1", "gocode.release.signed-envelope-inventory/1", "gocode.release.signed-envelope-verification-report/1", "gocode.release.unsigned-candidate-manifest/1", "gocode.v1-platform-scope-claim-migration/1"]],
        "proof_of_possession": "A" * 86, "predecessor": "c" * 64,
        "predecessor_schema_version": "gocode.project-owner.trust-config/2",
    }


class ProjectOwnerTrustV3SchemaTests(unittest.TestCase):
    def test_rust_v3_pins_hash_exact_schema_source_bytes(self) -> None:
        source = (ROOT / "crates/project-owner-authority/src/trust_v3.rs").read_text()
        pairs = re.findall(r'"(gocode\.[^"]+/\d+)",\s*"([0-9a-f]{64})"', source)
        actual = dict(pairs)
        expected = {
            schema_id: hashlib.sha256((ROOT / "docs/schemas" / filename).read_bytes()).hexdigest()
            for schema_id, filename in SOURCES.items()
        }
        self.assertEqual(actual, expected)

    def test_v3_is_closed_to_v2_predecessors_and_finalized_pins(self) -> None:
        schema = json.loads((ROOT / "docs/schemas/project-owner-trust-config-v3.schema.json").read_text())
        value = config()
        self.assertFalse(_errors(schema, value))
        self.assertFalse(trust_v3_errors(value))
        value["schema_digests"].pop()
        self.assertTrue(trust_v3_errors(value))
        value["predecessor_schema_version"] = "gocode.project-owner.trust-config/1"
        self.assertTrue(_errors(schema, value) or trust_v3_errors(value))


if __name__ == "__main__":
    unittest.main()
