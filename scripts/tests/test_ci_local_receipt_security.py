import contextlib
import copy
import importlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
INVENTORY = Path("scripts/rc0_candidate/inventories/source-candidate-v1.json")


class LocalInputReceiptSecurityTests(unittest.TestCase):
    def test_orchestrator_runs_only_canonical_gate_once(self):
        receipt_module = self._receipt_module()
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            marker = base / "gate-runs"
            repository = base / "repository"
            self._repository(repository, marker=marker)
            receipt = self._receipt_path(base / "receipt")
            receipt_module.run_local_input_gates(repository, receipt)
            self.assertEqual(marker.read_text(encoding="utf-8"), "run\n")
            self.assertTrue(receipt.exists())

    def test_old_issuer_and_alternate_script_cannot_publish(self):
        receipt_module = self._receipt_module()
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            self._repository(repository)
            receipt = self._receipt_path(base / "receipt")
            alternate = base / "alternate.sh"
            alternate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            self.assertFalse(hasattr(receipt_module, "issue_local_input_receipt"))
            with self.assertRaises(TypeError):
                receipt_module.run_local_input_gates(repository, receipt, alternate)
            self.assertFalse(receipt.exists())

            calls = []
            fake = lambda *args, **kwargs: calls.append((args, kwargs))
            with mock.patch.object(receipt_module, "issue_local_input_receipt", fake, create=True):
                result = receipt_module.main([
                    "issue", "--receipt", str(receipt), "--input-script", str(alternate),
                    "--pinned-rustc", "rustc 1.97.1 (8bab26f4f 2026-07-14)",
                    "--msrv-rustc", "rustc 1.95.0 (000000000 2026-01-01)",
                ])
            self.assertEqual(result, 2)
            self.assertEqual(calls, [])
            self.assertFalse(receipt.exists())
            self.assertEqual(
                receipt_module.main([
                    "run", "--receipt", str(receipt), "--input-script", str(alternate)
                ]),
                2,
            )
            self.assertFalse(receipt.exists())

    def test_failed_or_source_mutating_gate_cannot_publish(self):
        receipt_module = self._receipt_module()
        scripts = {
            "failed": "#!/bin/sh\nexit 7\n",
            "mutating": "#!/bin/sh\nprintf changed > tracked-state\n",
        }
        for name, script in scripts.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository = base / "repository"
                self._repository(repository, script=script, tracked_state=True)
                receipt = self._receipt_path(base / "receipt")
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.run_local_input_gates(repository, receipt)
                self.assertFalse(receipt.exists())

    def test_nonce_blocks_copied_and_restored_receipts(self):
        receipt_module = self._receipt_module()
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            self._repository(repository)
            first = self._receipt_path(base / "first")
            second = self._receipt_path(base / "second")
            receipt_module.run_local_input_gates(repository, first)
            raw = first.read_bytes()
            second.write_bytes(raw)
            second.chmod(0o600)
            receipt_module.validate_local_input_receipt(
                repository, first, repository / INVENTORY, consume=True,
            )
            self.assertFalse(first.exists())
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.validate_local_input_receipt(
                    repository, second, repository / INVENTORY, consume=True,
                )
            self.assertTrue(second.exists())
            first.write_bytes(raw)
            first.chmod(0o600)
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.validate_local_input_receipt(
                    repository, first, repository / INVENTORY, consume=True,
                )
            self.assertTrue(first.exists())

    def test_concurrent_nonce_consumers_have_exactly_one_winner(self):
        receipt_module = self._receipt_module()
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            self._repository(repository)
            first = self._receipt_path(base / "first")
            second = self._receipt_path(base / "second")
            receipt_module.run_local_input_gates(repository, first)
            second.write_bytes(first.read_bytes())
            second.chmod(0o600)

            def consume(path):
                try:
                    receipt_module.validate_local_input_receipt(
                        repository, path, repository / INVENTORY, consume=True,
                    )
                    return "satisfied"
                except receipt_module.LocalInputReceiptError:
                    return "blocked"

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(consume, (first, second)))
            self.assertEqual(results.count("satisfied"), 1)
            self.assertEqual(results.count("blocked"), 1)
            self.assertEqual(sum(not path.exists() for path in (first, second)), 1)

    def test_receipt_is_bound_to_original_worktree_identity(self):
        receipt_module = self._receipt_module()
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            clone = base / "clone"
            self._repository(repository)
            original = self._receipt_path(base / "original")
            copied = self._receipt_path(base / "copied")
            receipt_module.run_local_input_gates(repository, original)
            subprocess.run(["git", "clone", "--quiet", str(repository), str(clone)], check=True)
            (clone / ".git").chmod(0o700)
            copied.write_bytes(original.read_bytes())
            copied.chmod(0o600)
            with self.assertRaises(receipt_module.LocalInputReceiptError):
                receipt_module.validate_local_input_receipt(
                    clone, copied, clone / INVENTORY, consume=True,
                )
            self.assertTrue(copied.exists())
            receipt_module.validate_local_input_receipt(
                repository, original, repository / INVENTORY, consume=True,
            )
            self.assertFalse(original.exists())

    def test_ledger_symlink_wrong_mode_and_corrupt_nonce_fail_closed(self):
        receipt_module = self._receipt_module()
        for defect in ("symlink", "wrong-mode", "corrupt"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as location:
                base = Path(location)
                repository = base / "repository"
                self._repository(repository)
                receipt = self._receipt_path(base / "receipt")
                record = receipt_module.run_local_input_gates(repository, receipt)
                ledger = repository / ".git/gocode-local-input-nonces-v1"
                if defect == "symlink":
                    target = base / "ledger-target"
                    target.mkdir(mode=0o700)
                    ledger.symlink_to(target, target_is_directory=True)
                else:
                    ledger.mkdir(mode=0o700)
                    if defect == "wrong-mode":
                        ledger.chmod(0o755)
                    else:
                        tombstone = ledger / f'{record["receipt_nonce"]}.json'
                        tombstone.write_bytes(b"not-canonical")
                        tombstone.chmod(0o600)
                with self.assertRaises(receipt_module.LocalInputReceiptError):
                    receipt_module.validate_local_input_receipt(
                        repository, receipt, repository / INVENTORY, consume=True,
                    )
                self.assertTrue(receipt.exists())

    def test_malformed_types_are_blocked_without_consuming_or_claiming(self):
        receipt_module = self._receipt_module()
        canonical = importlib.import_module("scripts.rc0_policy.canonical")
        candidate = importlib.import_module("scripts.rc0_candidate.cli")
        with tempfile.TemporaryDirectory() as location:
            base = Path(location)
            repository = base / "repository"
            self._repository(repository)
            receipt = self._receipt_path(base / "receipt")
            valid = receipt_module.run_local_input_gates(repository, receipt)
            cases = {
                "record": [],
                "schema": self._changed(valid, "schema", []),
                "nonce": self._changed(valid, "receipt_nonce", 7),
                "issued": self._changed(valid, "issued_at_unix", True),
                "inputs": self._changed(valid, "local_inputs", {}),
                "revision": self._changed(valid, "source_revision", []),
                "tree": self._changed(valid, "source_tree", {}),
                "repository": self._changed(valid, "repository_identity", []),
                "repository-value": self._nested(valid, "repository_identity", "git_dir_ino", True),
                "script": self._changed(valid, "input_script_sha256", 4),
                "inventories": self._changed(valid, "inventories", []),
                "inventory-value": self._nested(valid, "inventories", "phase3_sha256", 1),
                "executables": self._changed(valid, "executables", []),
                "executable-record": self._nested(valid, "executables", "bash", []),
                "toolchains": self._changed(valid, "toolchains", []),
                "toolchain-value": self._nested(valid, "toolchains", "pinned", {}),
                "toolchain-mapping": self._nested(
                    valid, "toolchains", "pinned", valid["toolchains"]["msrv"]
                ),
                "gates": self._changed(valid, "gate_results", {}),
                "gate-entry": self._changed(valid, "gate_results", [[]]),
                "gate-name": self._gate_changed(valid, "gate", []),
                "gate-result": self._gate_changed(valid, "result", {}),
                "exit-status": self._changed(valid, "gate_exit_status", False),
            }
            for name, malformed in cases.items():
                with self.subTest(name=name):
                    receipt.write_bytes(canonical.canonical_bytes(malformed))
                    result = self._candidate(candidate, repository, receipt)
                    self.assertEqual(result, (2, "BLOCKED\n", ""))
                    self.assertTrue(receipt.exists())
            receipt.write_bytes(canonical.canonical_bytes(valid))
            result = self._candidate(candidate, repository, receipt)
            self.assertEqual(result, (0, "FIXTURE_LOCAL_INPUTS_SATISFIED\n", ""))
            self.assertFalse(receipt.exists())

    @staticmethod
    def _receipt_module():
        return importlib.import_module("scripts.ci_local_receipt")

    @staticmethod
    def _receipt_path(directory):
        directory.mkdir(mode=0o700)
        return directory / "local-inputs-receipt.json"

    @staticmethod
    def _changed(record, field, value):
        changed = copy.deepcopy(record)
        changed[field] = value
        return changed

    @staticmethod
    def _nested(record, field, nested, value):
        changed = copy.deepcopy(record)
        changed[field][nested] = value
        return changed

    @staticmethod
    def _gate_changed(record, field, value):
        changed = copy.deepcopy(record)
        changed["gate_results"][0][field] = value
        return changed

    @staticmethod
    def _candidate(candidate, repository, receipt):
        stdout, stderr = io.StringIO(), io.StringIO()
        arguments = ("fixture-local-inputs", "--receipt", str(receipt),
                     "--inventory", str(repository / INVENTORY))
        with mock.patch.object(candidate, "_ROOT", repository), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = candidate.main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def _repository(root, *, marker=None, script=None, tracked_state=False):
        (root / "scripts/rc0_candidate/inventories").mkdir(parents=True)
        (root / "docs/rc0").mkdir(parents=True)
        for relative in (
            INVENTORY,
            Path("scripts/rc0_candidate/inventories/local-reliability-v1.json"),
            Path("scripts/rc0_candidate/inventories/phase3-v1.json"),
            Path("docs/rc0/taxonomy-migration-v1.json"),
        ):
            shutil.copy2(ROOT / relative, root / relative)
        if script is None:
            script = "#!/bin/sh\nset -eu\n"
            if marker is not None:
                script += f'printf "run\\n" >> "{marker}"\n'
        (root / "scripts/ci-local-inputs.sh").write_text(script, encoding="utf-8")
        if tracked_state:
            (root / "tracked-state").write_text("original", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        (root / ".git").chmod(0o700)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "fixture"], check=True)


if __name__ == "__main__":
    unittest.main()
