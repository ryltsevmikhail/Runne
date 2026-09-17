"""Qualification native protocol must remain inside the audited adapter."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "qualification_xpc_architecture", Path(__file__).parents[1] / "validate_architecture.py"
)
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


class QualificationXpcBoundaryTests(unittest.TestCase):
    def test_separate_qualification_protocol_cannot_escape_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = root / "crates/runne-macos-xpc"
            (adapter / "src").mkdir(parents=True)
            (adapter / "Cargo.toml").write_text('[lints.rust]\nunsafe_code = "allow"\n')
            native = 'extern_protocol!(#[name = "RunneQualificationRunnerXpcProtocolV1"] unsafe trait Protocol {});\n'
            (adapter / "src/lib.rs").write_text(native)
            self.assertEqual([], architecture.find_macos_xpc_source_violations(root))
            for owner in ("crates/foreign/src", "apps/desktop/src-tauri/src"):
                foreign = root / owner
                foreign.mkdir(parents=True)
                source = foreign / "lib.rs"
                source.write_text(native)
                self.assertTrue(architecture.find_macos_xpc_source_violations(root))
                source.unlink()


if __name__ == "__main__":
    unittest.main()
