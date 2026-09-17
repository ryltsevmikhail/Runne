"""Keep the native case wire inventory aligned with the evidence verifier."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[1]
sys.path.insert(0, str(PACKAGE))
from contract import SELECTORS


class RustCaseInventoryTests(unittest.TestCase):
    def test_native_wire_inventory_exactly_matches_verifier(self) -> None:
        source = (ROOT / "crates/runne-api/src/qualification_case_control/model.rs").read_text()
        declaration = re.search(
            r"pub const QUALIFICATION_CASE_SELECTORS: \[&str; 54\] = (\[.*?\]);",
            source, re.DOTALL,
        )
        self.assertIsNotNone(declaration, "missing explicit immutable native inventory")
        values = json.loads(re.sub(r",\s*\]$", "]", declaration[1]))
        self.assertEqual(values, sorted(SELECTORS))
        self.assertEqual(len(values), 54)


if __name__ == "__main__":
    unittest.main()
