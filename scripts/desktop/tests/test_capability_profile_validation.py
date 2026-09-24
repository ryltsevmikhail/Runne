import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/desktop"))

from capability_manifest_impl.validation import validate_status


class CapabilityProfileValidationTests(unittest.TestCase):
    def test_historical_status_accepts_profile_v2(self):
        definition = json.loads((ROOT / "docs/profiles/desktop-v1-capabilities-v1.json").read_text())
        status = json.loads((ROOT / "docs/evidence/desktop-v1-capability-status-v2.json").read_text())
        self.assertEqual(validate_status(definition, status), ())

    def test_status_accepts_successor_profile_v3(self):
        definition = json.loads((ROOT / "docs/profiles/desktop-v1-capabilities-v1.json").read_text())
        status = json.loads((ROOT / "docs/evidence/desktop-v1-capability-status-v2.json").read_text())
        status["contract"]["profile_id"] = "gocode-ui-client/3"
        self.assertEqual(validate_status(definition, status), ())

    def test_status_rejects_unknown_profile(self):
        definition = json.loads((ROOT / "docs/profiles/desktop-v1-capabilities-v1.json").read_text())
        status = json.loads((ROOT / "docs/evidence/desktop-v1-capability-status-v2.json").read_text())
        status["contract"]["profile_id"] = "gocode-ui-client/4"
        errors = validate_status(definition, status)
        self.assertIn("STATUS_CONTRACT", errors)


if __name__ == "__main__":
    unittest.main()
