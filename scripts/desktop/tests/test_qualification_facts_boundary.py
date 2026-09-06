import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).parents[1] / "validate_architecture.py"
SPEC = importlib.util.spec_from_file_location("qualification_facts_architecture", MODULE)
architecture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(architecture)


def packages():
    dependency = {
        "name": "runne-native-qualification", "kind": None, "req": "*",
        "features": [], "uses_default_features": True, "source": None,
        "path": "/repo/crates/runne-native-qualification", "registry": None,
        "target": 'cfg(target_os = "macos")', "rename": None, "optional": False,
    }
    result = [{"name": owner, "dependencies": [dict(dependency)]}
              for owner in ("runne-desktop", "runne-platform-desktop", "runne-daemon")]
    result += [{"name": "runne-provider", "dependencies": [dict(dependency, target=None)]},
               {"name": "runne-store", "dependencies": [dict(dependency, target=None, kind="dev", features=["test-support"])]},
               {"name": "runne-native-qualification", "dependencies": [],
                "manifest_path": "/repo/crates/runne-native-qualification/Cargo.toml"}]
    return result


class QualificationFactsBoundary(unittest.TestCase):
    def test_only_exact_provider_facts_and_store_fixture_edges_are_admitted(self):
        self.assertEqual([], architecture.find_native_qualification_admission_dependency_violations(packages()))
        for index, field, value in (
            (3, "features", ["test-support"]), (3, "kind", "dev"),
            (3, "target", 'cfg(target_os = "macos")'), (3, "rename", "native"),
            (3, "path", "/evil/runne-native-qualification"), (4, "kind", None),
            (4, "features", []), (4, "optional", True),
        ):
            mutated = packages()
            mutated[index]["dependencies"][0][field] = value
            self.assertNotEqual([], architecture.find_native_qualification_admission_dependency_violations(mutated))
        duplicate = packages()
        duplicate.append(copy.deepcopy(duplicate[3]))
        self.assertNotEqual([], architecture.find_native_qualification_admission_dependency_violations(duplicate))

    def test_provider_edge_cannot_import_transport_verifier_or_filesystem(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/runne-provider/src/credential/enrollment/authority/qualification.rs"
            source.parent.mkdir(parents=True)
            source.write_text("use runne_native_qualification::VerifiedQualificationFenceFacts;\n")
            self.assertEqual([], architecture.find_native_qualification_admission_surface_violations(root))
            for payload in (
                "use runne_native_qualification::PendingQualificationAdmission;",
                "use runne_native_qualification::QualificationAdmissionVerifier;",
                "use runne_native_qualification::QualificationFaultRelayCodecV1;",
                "use std::fs as disk;",
                "use std::{env as process_env};",
            ):
                source.write_text(payload)
                self.assertNotEqual([], architecture.find_native_qualification_admission_surface_violations(root))


if __name__ == "__main__":
    unittest.main()
