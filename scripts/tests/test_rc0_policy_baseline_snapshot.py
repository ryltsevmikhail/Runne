import hashlib
from pathlib import Path
import unittest

from scripts.rc0_policy.schemas import SCHEMA_FILES, load_schema


ROOT = Path(__file__).resolve().parents[2]


class Rc0PolicyBaselineSnapshotTests(unittest.TestCase):
    def test_profile_three_schema_mapping_and_bytes_match_rc0_baseline(self) -> None:
        expected_files = {
            "gocode.rc0.schema.candidate-record/3": "rc0-candidate-record-v3.schema.json",
            "gocode.rc0.schema.source-gate-results/3": "rc0-source-gate-results-v3.schema.json",
            "gocode.rc0.schema.test-inventory/3": "rc0-test-inventory-v3.schema.json",
            "gocode.rc0.schema.security-validation/3": "rc0-security-validation-v3.schema.json",
            "gocode.rc0.schema.documentation-validation/3": "rc0-documentation-validation-v3.schema.json",
            "gocode.rc0.schema.fail-closed-disposition/3": "rc0-fail-closed-disposition-v3.schema.json",
            "gocode.rc0.schema.artifact-inventory/3": "rc0-artifact-inventory-v3.schema.json",
            "gocode.rc0.schema.sbom-spdx-2.3/3": "rc0-sbom-spdx-2.3-v3.schema.json",
            "gocode.rc0.schema.checksums-text/3": "rc0-checksums-text-v3.schema.json",
            "gocode.rc0.schema.qualification-policy-bundle/3": "rc0-qualification-policy-bundle-v3.schema.json",
            "gocode.rc0.schema.verification-report/3": "rc0-verification-report-v3.schema.json",
        }
        expected_sha256 = {
            "gocode.rc0.schema.candidate-record/3": "63333aea4cc1357d7e9d25bcc6368b2fe651ee3d92c0804864df50f2fe5715c4",
            "gocode.rc0.schema.source-gate-results/3": "3c43e824462dfb23afe3c8e961e1e64dd004c19b98f92efbd29eaa0fe52963a8",
            "gocode.rc0.schema.test-inventory/3": "d12a1461ce732546b68b8b60d7e0513973ae113c002fd8f71008873c6ee89fb5",
            "gocode.rc0.schema.security-validation/3": "3d706f42ab8e917496e9d2ac6b99f07b6a48f6acc138e072664ef03f7d20baaa",
            "gocode.rc0.schema.documentation-validation/3": "815ad8317e8e13097aa24d43d09ef87a87bae97524f9f83f07430207bda4cc86",
            "gocode.rc0.schema.fail-closed-disposition/3": "833bb432fafa1609261d15f766e800b7bb158ae904d871e9fa17cc94d1408224",
            "gocode.rc0.schema.artifact-inventory/3": "8610f9a620631f31ce3029ec8e9b7676674849cae63a5298ea426aba31f2a8f1",
            "gocode.rc0.schema.sbom-spdx-2.3/3": "fa9a83873c2282ab5b1af53bd84b67d1fdba21d87f191c7cff19a16bca2dfc25",
            "gocode.rc0.schema.checksums-text/3": "cbd8c767ea275236ae08d043b426c93b9f10665602e28a565b60a48160d5eb8d",
            "gocode.rc0.schema.qualification-policy-bundle/3": "4a44b28b633c350768d5960f8b480a9764d4b0781b01a255063dd3e08f1e4951",
            "gocode.rc0.schema.verification-report/3": "af24c4be574feffb0f575ffdf87e08b9176cf69e32904c2413bbaffc98b1c858",
        }

        self.assertEqual(SCHEMA_FILES, expected_files)
        self.assertEqual(tuple(SCHEMA_FILES), tuple(expected_files))
        for schema_id, filename in expected_files.items():
            with self.subTest(schema_id=schema_id):
                self.assertEqual(
                    hashlib.sha256((ROOT / "docs" / "schemas" / filename).read_bytes()).hexdigest(),
                    expected_sha256[schema_id],
                )
                self.assertEqual(load_schema(schema_id)["$id"], schema_id)


if __name__ == "__main__":
    unittest.main()
