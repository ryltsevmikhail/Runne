from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

from codec import Rejected, canonical, digest
from contract import DEPLOYMENT, ROLE_PATHS, SELECTORS
from controller import STAGES, _attestation_receipt, handoff
from package_subject import canonical_roles, open_package, signed_subject, snapshot, subject
from process_control import _alive, run
from policy import MODULES


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_terminated(case: unittest.TestCase, pid: int, message: str) -> None:
    for _ in range(20):
        if not _alive(pid): return
        time.sleep(0.05)
    case.fail(message)


class ControllerTests(unittest.TestCase):
    def setup_case(self, directory: str, *, drift: bool = False,
                   preflight_boolean: str | None = None, terminal_boolean: str | None = None):
        root = Path(directory); package = root / "package"; package.mkdir()
        (package / "candidate").write_text("exact bytes")
        for path in ROLE_PATHS.values():
            role = package / path; role.parent.mkdir(parents=True, exist_ok=True)
            role.write_bytes(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01role")
        verifier = root / "verifier"; verifier.write_text("verifier")
        executor = root / "executor.py"
        mutation = f"Path({str(package / 'candidate')!r}).write_text('drift')" if drift else ""
        preflight_values = {name: 1 if name == preflight_boolean else True for name in (
            "developer_id_verified", "notarized", "provisioning_verified"
        )}
        terminal_values = {name: 1 if name == terminal_boolean else True for name in (
            "evidence_ready", "cleanup_verified"
        )}
        executor.write_text(
            f"#!{sys.executable} -I\nimport hashlib,json,sys\nfrom pathlib import Path\n"
            "value=json.load(sys.stdin)\n"
            "canonical=json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')\n"
            "if not any(item.startswith('--package-fd=') for item in sys.argv): sys.exit(2)\n"
            "fd=int(next(item.split('=',1)[1] for item in sys.argv if item.startswith('--package-fd=')))\n"
            "if '--preflight' in sys.argv:\n"
            " result={'schema_version':'runne/native-dpk-preflight-result/v1',"
            "'request_sha256':hashlib.sha256(canonical).hexdigest(),"
            "'package_snapshot_sha256':value['package_snapshot_sha256'],'package_subject_sha256':value['package_subject_sha256'],"
            f"'developer_id_verified':{preflight_values['developer_id_verified']!r},'notarized':{preflight_values['notarized']!r},'provisioning_verified':{preflight_values['provisioning_verified']!r},"
            "'role_paths':value['role_paths'],'role_measurements':value['role_measurements'],"
            "'deployment_sha256':value['deployment_sha256'],'attestation_sha256':value['attestation_sha256'],"
            "'attestation_receipt_sha256':value['attestation_receipt_sha256']}\n"
            " print(json.dumps(result,sort_keys=True,separators=(',',':')));sys.exit(0)\n"
            f"{mutation}\n"
            "result={'schema_version':'runne/native-dpk-controller-result/v1',"
            "'workflow_run_id':value['workflow_run_id'],'request_sha256':hashlib.sha256(canonical).hexdigest(),"
            "'package_snapshot_sha256':value['package_snapshot_sha256'],'package_subject_sha256':value['package_subject_sha256'],"
            f"'evidence_ready':{terminal_values['evidence_ready']!r},'cleanup_verified':{terminal_values['cleanup_verified']!r}}}\n"
            "print(json.dumps(result,sort_keys=True,separators=(',',':')))\n"
        ); executor.chmod(0o755)
        descriptor = open_package(str(package))
        try: measurement = subject(descriptor)
        finally: os.close(descriptor)
        request = {"schema_version":"runne/native-dpk-controller-request/v1",
                   "repository":"https://git@git.sourcecraft.dev/ryltsevmg/runne.git",
                   "workflow":"desktop-qualification","job":"qualification-native-macos",
                   "protected_ref":"refs/tags/v1.0.0","source_revision":"a"*40,
                   "candidate_sha256":hashlib.sha256(b"candidate").hexdigest(),
                   "release_tuple_v3_sha256":hashlib.sha256(b"release").hexdigest(),
                   "package_snapshot_sha256":digest(snapshot(measurement)), "package_subject_sha256":digest(signed_subject(measurement)), "workflow_run_id":"run-1",
                   "attestation_sha256":hashlib.sha256(b"attestation").hexdigest(),"attestation_receipt_sha256":"0" * 64,
                   "deployment_sha256":digest(DEPLOYMENT), "role_paths":ROLE_PATHS,"role_measurements":canonical_roles(measurement),
                   "selectors":sorted(SELECTORS), "stages":list(STAGES),
                   "executor_sha256":file_sha(executor)}
        public = bytes(32)
        policy = {"schema_version":"runne/sourcecraft-native-qualification-policy/v1",
                  "policy_id":"runne/writer-qualification/v1",
                  "repository":"https://git@git.sourcecraft.dev/ryltsevmg/runne.git",
                  "workflow":"desktop-qualification","job":"qualification-native-macos",
                  "protected_ref":"refs/tags/v1.0.0","source_revision":"a"*40,
                  "candidate_sha256":request["candidate_sha256"],
                  "release_tuple_v3_sha256":hashlib.sha256(b"release").hexdigest(),
                  "candidate_root":str(root / "candidate-root"),"package_root":str(package),
                  "controller":{"path":str(root / "controller"),"sha256":hashlib.sha256(b"c").hexdigest()},
                  "verifier":{"path":str(verifier),"sha256":file_sha(verifier)},
                  "native_executor":{"path":str(executor),"sha256":file_sha(executor)},
                  "attestation_verifier":{"path":str(root / "attestation"),"sha256":hashlib.sha256(b"a").hexdigest()},
                  "evidence_signer":{"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-sign-evidence","sha256":hashlib.sha256(b"s").hexdigest()},
                  "signer_broker":{"path":"/opt/gocode/sourcecraft/bin/sourcecraft-native-qualification-signer-broker","sha256":hashlib.sha256(b"b").hexdigest()},
                  "authority_modules":{name:{"path":str(root / name),"sha256":hashlib.sha256(name.encode()).hexdigest()} for name in MODULES},
                  "evidence_authority":{"key_id":hashlib.sha256(public).hexdigest(),"public_key":public.hex()},
                  "writer_profile":{"attestation":2,"prelude":1,"ack":1},"test_only":True}
        request["attestation_receipt_sha256"] = digest(_attestation_receipt(policy, request["workflow_run_id"], request["package_snapshot_sha256"], request["package_subject_sha256"], request["attestation_sha256"]))
        return request, policy, executor

    def test_controller_executes_exact_admitted_package(self):
        with tempfile.TemporaryDirectory() as directory:
            request, policy, executor = self.setup_case(directory)
            result = handoff(request, policy, production=False, executor=executor)
            self.assertTrue(result["native_execution"]); self.assertTrue(result["evidence_ready"])

    def test_build_request_accepts_real_workflow_identity_only(self):
        import controller
        with tempfile.TemporaryDirectory() as directory:
            _, policy, _ = self.setup_case(directory); root = Path(directory) / "evidence"; root.mkdir()
            (root / "sourcecraft-attestation.bundle").write_bytes(b"attestation")
            original, original_digest = controller.EVIDENCE_ROOT, controller.file_digest; controller.EVIDENCE_ROOT = root
            controller.file_digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            environment = {"SOURCECRAFT_REPO_URL":policy["repository"], "SOURCECRAFT_WORKFLOW":"desktop-qualification", "SOURCECRAFT_TASK":"qualification-native-macos", "SOURCECRAFT_COMMIT_REF":"refs/tags/v1.0.0", "SOURCECRAFT_COMMIT_SHA":"a" * 40, "SOURCECRAFT_RUN_ID":"run-1"}
            try:
                descriptor = open_package(policy["package_root"])
                try: measurement = subject(descriptor)
                finally: os.close(descriptor)
                request = controller.build_request(policy, environment)
                self.assertEqual(request["workflow"], "desktop-qualification")
                self.assertEqual(
                    request["package_snapshot_sha256"],
                    digest({name:item["sha256"] for name,item in measurement["files"].items()}),
                )
                for item in request["role_measurements"].values():
                    self.assertNotIn("device", item); self.assertNotIn("inode", item)
                for name in ("SOURCECRAFT_REPO_URL", "SOURCECRAFT_WORKFLOW", "SOURCECRAFT_TASK", "SOURCECRAFT_COMMIT_REF", "SOURCECRAFT_COMMIT_SHA", "SOURCECRAFT_RUN_ID"):
                    changed = dict(environment); changed[name] = "=" if name == "SOURCECRAFT_RUN_ID" else "different"
                    with self.assertRaises(Rejected): controller.build_request(policy, changed)
            finally:
                controller.EVIDENCE_ROOT = original; controller.file_digest = original_digest

    def test_controller_rejects_numeric_executor_booleans(self):
        cases = (
            ("preflight_boolean", "developer_id_verified"),
            ("preflight_boolean", "notarized"),
            ("preflight_boolean", "provisioning_verified"),
            ("terminal_boolean", "evidence_ready"),
            ("terminal_boolean", "cleanup_verified"),
        )
        for option, field in cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as directory:
                    request, policy, executor = self.setup_case(directory, **{option: field})
                    self.assertFalse(handoff(request, policy, production=False, executor=executor)["native_execution"])

    def test_controller_rejects_package_drift_across_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            request, policy, executor = self.setup_case(directory, drift=True)
            self.assertFalse(handoff(request, policy, production=False, executor=executor)["native_execution"])

    def test_controller_persists_bound_lifecycle_after_terminal_cleanup(self):
        from verifier import _lifecycle
        with tempfile.TemporaryDirectory() as directory:
            request, policy, executor = self.setup_case(directory); evidence = Path(directory) / "evidence"; evidence.mkdir()
            self.assertTrue(handoff(request, policy, production=False, executor=executor, evidence_root=evidence)["native_execution"])
            lifecycle = json.loads((evidence / "controller-lifecycle.json").read_text())
            self.assertEqual(lifecycle["order"], ["request", "preflight", "execute", "complete"])
            self.assertEqual(lifecycle["request_sha256"], digest(request))
            self.assertEqual(lifecycle["attestation_receipt_sha256"], request["attestation_receipt_sha256"])
            _lifecycle(lifecycle, {"workflow_run_id":request["workflow_run_id"]}, request["package_snapshot_sha256"],
                       request["package_subject_sha256"], request["attestation_sha256"], policy,
                       {"role_measurements":request["role_measurements"]})

    def test_controller_rejects_unbound_preflight_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            request, policy, executor = self.setup_case(directory); request["attestation_receipt_sha256"] = "0" * 64
            self.assertFalse(handoff(request, policy, production=False, executor=executor)["native_execution"])

    def test_timeout_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            script = Path(directory) / "hang.sh"
            script.write_text(f"#!/bin/sh\nsleep 30 & echo $! > {pid_file}\nwait\n"); script.chmod(0o755)
            with self.assertRaises(Exception): run([str(script)], None, timeout=0.2)
            child = int(pid_file.read_text())
            assert_terminated(self, child, "descendant survived process-group timeout")

    def test_output_limit_uses_one_over_limit_sentinel(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "output.py"
            script.write_text(f"#!{sys.executable} -I\nimport sys\nsys.stdout.write('x'*131073)\n"); script.chmod(0o755)
            with self.assertRaises(Rejected): run([str(script)], None, timeout=0.5)

    def test_stdin_no_read_obeys_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "no-read.sh"; script.write_text("#!/bin/sh\nsleep 30\n"); script.chmod(0o755)
            started = time.monotonic()
            with self.assertRaises(Rejected): run([str(script)], b"x" * (16 * 1024 * 1024), timeout=0.2)
            self.assertLess(time.monotonic() - started, 2)

    def test_setsid_descendant_is_rejected_and_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"; script = Path(directory) / "escape.sh"
            script.write_text(
                f"#!{sys.executable} -I\nimport os,time\n"
                f"pid=os.fork()\nif pid == 0:\n os.setsid();open({str(pid_file)!r},'w').write(str(os.getpid()));time.sleep(30)\nelse:\n time.sleep(3)\n"
            )
            script.chmod(0o755)
            with self.assertRaises(Rejected): run([str(script)], None, timeout=0.5)
            child = int(pid_file.read_text())
            assert_terminated(self, child, "setsid descendant survived containment")

    def test_darwin_uses_kernel_no_fork_containment(self):
        import process_control
        original, sandbox = process_control.sys.platform, process_control.SANDBOX_EXEC
        process_control.sys.platform, process_control.SANDBOX_EXEC = "darwin", Path("/usr/bin/env")
        try:
            command = process_control._contained(["/bin/true"])
        finally: process_control.sys.platform, process_control.SANDBOX_EXEC = original, sandbox
        self.assertEqual(command[:3], ["/usr/bin/env", "-p", process_control.SANDBOX_PROFILE])

    def test_linux_rejects_production_containment(self):
        import process_control
        original = process_control.sys.platform
        process_control.sys.platform = "linux"
        try:
            with self.assertRaises(Rejected): run(["/bin/true"], None, contain=True)
        finally: process_control.sys.platform = original

    @unittest.skipUnless(sys.platform.startswith("linux"), "pidfd cleanup is Linux-specific")
    def test_linux_cleanup_signals_pinned_pidfd(self):
        import process_control
        from unittest.mock import Mock, patch
        process = Mock(pid=999); process.wait.return_value = 0
        with patch.object(process_control.signal, "pidfd_send_signal") as send, \
             patch.object(process_control.os, "killpg", side_effect=ProcessLookupError):
            process_control._kill_group(process, {123: 7})
        send.assert_called_once_with(7, process_control.signal.SIGKILL)

    def test_success_rejects_and_kills_detached_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"; script = Path(directory) / "leak.sh"
            script.write_text(f"#!/bin/sh\nsleep 30 </dev/null >/dev/null 2>&1 & echo $! > {pid_file}\nprintf '{{}}'\n")
            script.chmod(0o755)
            with self.assertRaises(Rejected): run([str(script)], None)
            child = int(pid_file.read_text())
            assert_terminated(self, child, "successful leader left descendant alive")

    def test_stdin_broken_pipe_kills_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"; script = Path(directory) / "stdin-close.sh"
            script.write_text(
                f"#!/bin/sh\nsleep 30 & echo $! > {pid_file}\nexec 0<&-\nsleep 1\n"
            )
            script.chmod(0o755)
            with self.assertRaises(Rejected): run([str(script)], b"x" * (16 * 1024 * 1024))
            child = int(pid_file.read_text())
            assert_terminated(self, child, "stdin failure left descendant alive")


if __name__ == "__main__": unittest.main()
