from __future__ import annotations

import base64
import hashlib
import json
import os
import plistlib
import socket
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from codec import Rejected, canonical, digest, load_json
from contract import DEPLOYMENT, ROLE_PATHS
from native_checks import ARTIFACTS, _entitlements, _identity, _symbols, verify_roles
from vector_harness import evaluate
from conformance_support import _hash, _vector


class NativeConformanceTests(unittest.TestCase):
    def test_native_measurements_require_exact_typed_identity_and_entitlements(self) -> None:
        from codec import Rejected
        _identity("Authority=Developer ID Application: Runne (758F9Z45SR)\nIdentifier=runne\nTeamIdentifier=758F9Z45SR", "writer")
        with self.assertRaises(Rejected): _identity("Authority=Developer ID Application: Runne (758F9Z45SR)\nIdentifier=runne.extra\nTeamIdentifier=758F9Z45SR", "writer")
        plist = "<plist version=\"1.0\"><dict></dict></plist>"
        _entitlements(plist, "writer")
        with self.assertRaises(Rejected): _entitlements("<plist version=\"1.0\"><dict><key>extra</key><true/></dict></plist>", "writer")
        _symbols("                 U _SecItemCopyMatching")
        with self.assertRaises(Rejected): _symbols("                 U _SecKeychainOpen")

    def test_native_launch_agent_profile_and_notarization_parsers(self) -> None:
        import native_checks
        from unittest.mock import patch
        launch = {"Label":DEPLOYMENT["launch_agent_label"],"BundleProgram":DEPLOYMENT["bundle_program"],"KeepAlive":False,"RunAtLoad":False,"MachServices":DEPLOYMENT["mach_services"]}
        profile = {"Name":"Runne Service Distribution","UUID":"00000000-0000-0000-0000-000000000001","TimeToLive":365,"CreationDate":datetime(2026, 1, 1),"ExpirationDate":datetime(2027, 1, 1),"ApplicationIdentifierPrefix":["758F9Z45SR"],"Platform":["OSX"],"ProvisionsAllDevices":True,"TeamIdentifier":["758F9Z45SR"],"Entitlements":{"application-identifier":"758F9Z45SR.com.runne.credential-service","com.apple.developer.team-identifier":"758F9Z45SR","get-task-allow":False,"keychain-access-groups":["758F9Z45SR.com.runne.credential-service"]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launch-agent.plist"; path.write_bytes(plistlib.dumps(launch)); native_checks._launch_agent(path)
            with patch.object(native_checks, "_run", return_value=plistlib.dumps(profile).decode()): native_checks._profile(path, "service")
        native_checks._notarized("/Applications/Runne.app: accepted\nsource=Notarized Developer ID")
        with self.assertRaises(Rejected): native_checks._notarized("/Applications/Runne.app: rejected\nsource=Notarized Developer ID")

    def test_production_cli_rejects_arguments_and_test_policy(self) -> None:
        import subprocess
        result = subprocess.run([sys.executable, str(PACKAGE / "verifier.py"), "--policy", "/candidate/policy"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1); self.assertFalse(json.loads(result.stdout)["qualified"])

    def test_row_workflow_mismatch_is_rejected(self) -> None:
        value = _vector(); value["files"]["macos-13-arm64.json"]["runner"]["workflow_run_id"] = "other-run"
        with self.assertRaises(Rejected): evaluate(value)

    def test_fixed_shebang_does_not_use_path_python(self) -> None:
        import os, subprocess
        verifier = PACKAGE / "verifier.py"; verifier.chmod(0o755)
        if not Path("/usr/bin/python3").exists():
            self.assertEqual(verifier.read_text().splitlines()[0], "#!/usr/bin/python3 -I")
            self.skipTest("production shebang interpreter is unavailable on this structural runner")
        with tempfile.TemporaryDirectory() as directory:
            shim = Path(directory) / "python3"; shim.write_text("#!/bin/sh\nprintf '{\\\"qualified\\\":true}'\n"); shim.chmod(0o755)
            result = subprocess.run([str(verifier), "--bad"], env={"PATH":str(shim.parent)}, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1); self.assertIn('"qualified":false', result.stdout)

    def test_policy_leaf_permission_admission_is_descriptor_bound(self) -> None:
        from codec import load_installed_json
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "policy.json"; path.write_text("{}"); path.chmod(0o666)
            with self.assertRaises(Rejected): load_installed_json(path)

    def test_policy_requires_a_pinned_evidence_signer(self) -> None:
        from policy import validate
        policy = _vector()["policy"]
        assert isinstance(policy, dict)
        signer = {"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence","sha256":_hash("signer")}
        policy["evidence_signer"] = signer
        self.assertEqual(validate(policy, Path("/test/verifier"), False)["evidence_signer"], signer)
        policy["evidence_signer"] = {**signer, "path":"/test/other-signer"}
        with self.assertRaises(Rejected): validate(policy, Path("/test/verifier"), False)

    def test_installation_manifest_installs_reviewed_signer_source(self) -> None:
        import installation_manifest
        self.assertIn("signer.py", installation_manifest.INSTALL_FILES)
        self.assertEqual(installation_manifest.ENTRYPOINTS["signer_entry.py"], "sourcecraft-native-qualification-sign-evidence")

    def test_materialized_install_runs_every_entrypoint_without_import_error(self) -> None:
        import installation_manifest
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manifest = json.loads(subprocess.check_output([sys.executable, str(PACKAGE / "installation_manifest.py")]))
            for item in manifest["files"]:
                destination = root / "bin" / Path(item["destination"]).name
                destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes((PACKAGE / item["path"]).read_bytes()); destination.chmod(int(item["mode"], 8))
            for name in ("sourcecraft-native-qualification-controller", "sourcecraft-native-qualification-verifier", "sourcecraft-native-qualification-vector-harness", "sourcecraft-native-qualification-sign-evidence", "sourcecraft-native-qualification-signer-broker", "sourcecraft-native-qualification-request-signature"):
                entrypoint = root / "bin" / name
                command = [str(entrypoint), "--rejected"] if Path("/usr/bin/python3").exists() else [sys.executable, "-I", str(entrypoint), "--rejected"]
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_provisioning_rejects_a_profile_without_distribution_metadata(self) -> None:
        import native_checks
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile.mobileprovision"
            profile.write_bytes(plistlib.dumps({"Entitlements": DEPLOYMENT["entitlements"]["service"]}))
            original = native_checks._run; native_checks._run = lambda _: profile.read_text()
            try:
                with self.assertRaises(Rejected): native_checks._profile(profile, "service")
            finally:
                native_checks._run = original

    def test_provisioning_requires_the_qualification_time_to_be_in_window(self) -> None:
        import native_checks
        profile = {"Name":"Runne Service Distribution","UUID":"00000000-0000-0000-0000-000000000001","TimeToLive":365,"CreationDate":datetime(2026, 1, 1, tzinfo=timezone.utc),"ExpirationDate":datetime(2027, 1, 1, tzinfo=timezone.utc),"ApplicationIdentifierPrefix":["758F9Z45SR"],"Platform":["OSX"],"ProvisionsAllDevices":True,"TeamIdentifier":["758F9Z45SR"],"Entitlements":{"application-identifier":"758F9Z45SR.com.runne.credential-service","com.apple.developer.team-identifier":"758F9Z45SR","get-task-allow":False,"keychain-access-groups":["758F9Z45SR.com.runne.credential-service"]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile"; path.write_bytes(plistlib.dumps(profile))
            original = native_checks._run; native_checks._run = lambda _: path.read_text()
            try:
                native_checks._profile(path, "service", datetime(2026, 6, 1, tzinfo=timezone.utc))
                with self.assertRaises(Rejected): native_checks._profile(path, "service", datetime(2027, 1, 1, tzinfo=timezone.utc))
            finally: native_checks._run = original

    def test_private_seed_rejects_readable_permissions(self) -> None:
        from signer import _seed
        policy = _vector()["policy"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seed"; path.write_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")); path.chmod(0o644)
            with self.assertRaises(Rejected): _seed(path, policy, production=False)

    def test_staged_privileged_module_mutation_is_rejected_before_issuance(self) -> None:
        import policy as policy_module
        from policy import MODULES, verify_authority_modules
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); modules = {}
            for name in MODULES:
                target = root / name; target.write_bytes((PACKAGE / name).read_bytes())
                modules[name] = {"path":str(target), "sha256":hashlib.sha256(target.read_bytes()).hexdigest()}
            with patch.object(policy_module, "installed"):
                verify_authority_modules({"authority_modules":modules})
                (root / "signer.py").write_text("tampered")
                with self.assertRaises(Rejected): verify_authority_modules({"authority_modules":modules})

    def test_production_path_admission_has_an_isolated_root_and_rejects_later_symlinks(self) -> None:
        from policy import installed
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); policy = root / "etc/policy.json"; policy.parent.mkdir(); policy.write_text("{}")
            installed(policy, owner=os.getuid(), boundary=root)
            alias = root / "etc/alias"; alias.symlink_to(policy)
            with self.assertRaises(Rejected): installed(alias, owner=os.getuid(), boundary=root)

    def test_verify_roles_accepts_complete_synthetic_redacted_macos_measurements(self) -> None:
        import native_checks
        fixtures = PACKAGE / "tests/fixtures/macos-runner-synthetic-redacted"
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "Runne.app"; package.mkdir()
            for role, relative in ROLE_PATHS.items():
                target = package / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(role.encode())
            for name, relative in ARTIFACTS.items():
                target = package / relative; target.parent.mkdir(parents=True, exist_ok=True)
                source = fixtures / ({"launch_agent_plist_sha256":"launch-agent.plist","provisioning_sha256":"service.mobileprovision"}.get(name, "artifact.bin"))
                target.write_bytes(source.read_bytes())
            desktop = package / "Contents/embedded.provisionprofile"; desktop.parent.mkdir(parents=True, exist_ok=True); desktop.write_bytes((fixtures / "desktop.mobileprovision").read_bytes())
            digest_file = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            tuple_value = {name: digest_file(package / relative) for name, relative in ARTIFACTS.items()}
            def output(command: list[str]) -> str:
                target = Path(command[-1])
                if command[0].endswith("security"): return target.read_text()
                if command[0].endswith("spctl"): return (fixtures / "spctl.txt").read_text()
                if command[0].endswith("nm"): return (fixtures / "nm.txt").read_text()
                role = next(name for name, relative in ROLE_PATHS.items() if str(target).endswith(relative))
                return (fixtures / (f"entitlements-{role}.plist" if "--entitlements" in command else f"codesign-{role}.txt")).read_text()
            original, original_digest = native_checks._run, native_checks.file_digest
            native_checks._run, native_checks.file_digest = output, digest_file
            try: verify_roles(package, tuple_value)
            finally: native_checks._run, native_checks.file_digest = original, original_digest

    def test_signer_emits_an_envelope_from_the_completed_controller_lifecycle(self) -> None:
        from signer import issue
        from verifier import verify_test_vector
        value = _vector(); files, package = value["files"], value["package"]
        assert isinstance(files, dict) and isinstance(package, dict)
        files.pop("signed-envelope.json")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(); evidence = base / "evidence"; evidence.mkdir(); installed = base / "package"; installed.mkdir()
            for name, item in files.items(): evidence.joinpath(name).write_bytes(canonical(item) if not isinstance(item, str) else item.encode())
            for name, item in package.items():
                target = installed / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(base64.b64decode(item["base64"]))
            policy = dict(value["policy"]); policy["package_root"] = str(installed)
            seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"); key = base / "authority.seed"; key.write_bytes(seed); key.chmod(0o600)
            envelope = issue(policy, evidence, key, production=False)
            self.assertEqual(envelope["controller_lifecycle_sha256"], digest(files["controller-lifecycle.json"]))
            self.assertTrue(verify_test_vector(policy, evidence, datetime.now(timezone.utc), Path("/test/verifier"), value["attestation"])["qualified"])
            with self.assertRaises(Rejected): issue(policy, evidence, key, production=False)

    def test_signer_cli_rejects_caller_selected_key_or_evidence(self) -> None:
        import subprocess
        result = subprocess.run([sys.executable, str(PACKAGE / "signer.py"), "--key", "/candidate/key"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)

    def test_signer_request_ends_its_fixed_frame_before_waiting_for_reply(self) -> None:
        import signer_request
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sign.sock"; listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); listener.bind(str(path)); listener.listen(1)
            received: list[bytes] = []
            def serve() -> None:
                connection, _ = listener.accept()
                with connection:
                    received.append(connection.recv(7)); connection.settimeout(0.2)
                    try: received.append(connection.recv(1))
                    except TimeoutError: received.append(b"timeout")
                    connection.sendall(b"ok\n")
            worker = threading.Thread(target=serve); worker.start(); original = signer_request.SOCKET; signer_request.SOCKET = path
            try: self.assertEqual(signer_request.main([]), 0)
            finally: signer_request.SOCKET = original; worker.join(timeout=1); listener.close()
            self.assertEqual(received, [b"issue\n", b""])

    def test_descriptor_loader_rejects_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / "target").mkdir(); (root / "target" / "proof.json").write_text("{}")
            (root / "alias").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaises(Rejected): load_json(root / "alias" / "proof.json")
