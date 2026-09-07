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
    result += [{"name": "runne-provider", "dependencies": [
                   dict(dependency, target=None),
                   dict(dependency, target=None, kind="dev", features=["test-support"]),
               ]},
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
        missing_fixture_feature = packages()
        missing_fixture_feature[3]["dependencies"][1]["features"] = []
        self.assertNotEqual([], architecture.find_native_qualification_admission_dependency_violations(missing_fixture_feature))

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

    def test_only_private_writer_receiver_may_consume_native_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receiver = root / (
                "crates/runne-provider/src/credential/enrollment/protocol/"
                "session_attestation/qualified/receiver.rs"
            )
            receiver.parent.mkdir(parents=True)
            allowed = (
                "use runne_native_qualification::{PendingQualificationAdmission, "
                "QualificationAdmissionVerifier, QualificationProcessRole, "
                "VerifiedQualificationFault};\n"
                "fn consume() { verifier.verify_exact_writer_fault_borrowed(); }\n"
            )
            receiver.write_text(allowed)
            self.assertEqual(
                [],
                architecture.find_native_qualification_admission_surface_violations(root),
            )

            for path, payload in (
                (receiver, allowed + "use std::fs as disk;\n"),
                (receiver, allowed + "fn verify(callback: impl FnOnce()) {}\n"),
                (receiver, allowed + "pub fn from_raw(candidate_sha256: [u8; 32]) {}\n"),
                (receiver.with_name("bypass.rs"), allowed),
                (root / "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/qualification_fence.rs", "fn consume() { verifier.verify_exact_writer_fault_borrowed(); }\n"),
                (root / "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/qualification_fence.rs", "fn consume() { QualificationAdmissionVerifier::verify_exact_writer_fault_borrowed(&mut verifier); }\n"),
                (root / "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/qualification_fence.rs", "use runne_native_qualification::QualificationAdmissionVerifier as Q;\nfn consume() { Q::verify_exact_writer_fault_borrowed(&mut verifier); }\n"),
                (root / "crates/runne-daemon/src/protected_activation/control_v3/initial_exchange/qualification_fence.rs", "pub use runne_native_qualification::QualificationAdmissionVerifier as Q;\nfn consume() { Q::verify_exact_writer_fault_borrowed(&mut verifier); }\n"),
            ):
                receiver.write_text(allowed)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload)
                self.assertNotEqual(
                    [],
                    architecture.find_native_qualification_admission_surface_violations(root),
                )
                if path != receiver:
                    path.unlink()

    def test_native_writer_transition_exemptions_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admission = root / "crates/runne-native-qualification/src/admission.rs"
            admission.parent.mkdir(parents=True)
            exact = "fn verify_exact_writer_fault_borrowed() {}\n"
            service = "fn verify_exact_service_fault_borrowed() {}\n"
            admission.write_text(exact + service)
            self.assertEqual(
                [],
                architecture.find_native_qualification_admission_surface_violations(root),
            )

            admission.write_text(exact * 2 + service)
            self.assertNotEqual(
                [],
                architecture.find_native_qualification_admission_surface_violations(root),
            )

            admission.write_text(exact + service)
            neighbor = admission.with_name("bypass.rs")
            neighbor.write_text(exact)
            self.assertNotEqual(
                [],
                architecture.find_native_qualification_admission_surface_violations(root),
            )

    def test_service_transition_has_zero_external_production_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = (
                "fn consume() { verifier.verify_exact_service_fault_borrowed(); }\n",
                "fn consume() { QualificationAdmissionVerifier::verify_exact_service_fault_borrowed(&mut verifier); }\n",
                "use runne_native_qualification::QualificationAdmissionVerifier as Q;\nfn consume() { Q::verify_exact_service_fault_borrowed(&mut verifier); }\n",
                "pub use runne_native_qualification::QualificationAdmissionVerifier as Q;\nfn consume() { Q::verify_exact_service_fault_borrowed(&mut verifier); }\n",
            )
            external_mutations = (
                ("crates/runne-daemon/src/qualification.rs", calls[0]),
                ("crates/runne-credential-service/src/qualification.rs", calls[1]),
                ("crates/runne-provider/src/qualification.rs", calls[2]),
                ("crates/runne-secure-store/src/qualification.rs", calls[3]),
            )
            include_paths = (
                "crates/runne-secure-store/src/macos/implementation_parts/"
                "provider_credential_store.inc",
                "crates/runne-native-qualification/src/admission_parts/service.inc",
            )
            include_mutations = tuple(
                (relative, payload) for relative in include_paths for payload in calls
            )
            for relative, payload in external_mutations + include_mutations:
                path = root / relative
                self.assertEqual(
                    [],
                    architecture.find_native_qualification_admission_surface_violations(root),
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload)
                self.assertNotEqual(
                    [],
                    architecture.find_native_qualification_admission_surface_violations(root),
                )
                path.unlink()
                self.assertEqual(
                    [],
                    architecture.find_native_qualification_admission_surface_violations(root),
                )

if __name__ == "__main__":
    unittest.main()
