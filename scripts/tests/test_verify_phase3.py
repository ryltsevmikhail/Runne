"""End-to-end shell contracts for strict Phase 3 tuple evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[2]
VERIFY = ROOT / "scripts/verify-phase3.sh"
INVENTORY = ROOT / "scripts/rc0_candidate/inventories/source-candidate-v1.json"


class VerifyPhase3Tests(unittest.TestCase):
    def test_verifier_binds_package_target_test_source_toolchain_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._copy_verifier(root)
            log = root / "commands.log"
            self._write_commands(root, log)
            result = self._run(root)
            commands = log.read_text().splitlines()
            expected_count = self._phase3_record_count()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("source_sha=0123456789abcdef0123456789abcdef01234567", output)
        self.assertIn("toolchain=rustc fixture", output)
        self.assertIn("inventory_digest=", output)
        self.assertEqual(sum(" -- --list" in command for command in commands), expected_count)
        self.assertEqual(sum(" -- --exact" in command for command in commands), expected_count)

    def test_shell_never_runs_a_whole_target_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._copy_verifier(root)
            log = root / "commands.log"
            self._write_commands(root, log)
            result = self._run(root)
            commands = log.read_text().splitlines()
            expected_count = self._phase3_record_count()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        exact = [command for command in commands if " -- --exact" in command]
        self.assertEqual(len(exact), expected_count)
        for command in exact:
            parts = command.split()
            target = parts[parts.index("--test") + 1]
            separator = parts.index("--")
            self.assertNotEqual(parts[separator - 1], target)

    def _copy_verifier(self, root: Path) -> None:
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copy2(VERIFY, scripts / "verify-phase3.sh")
        shutil.copy2(ROOT / "scripts/phase3_inventory.py", scripts / "phase3_inventory.py")
        (scripts / "validate-docs.py").write_text("raise SystemExit(0)\n")
        inventory = root / "scripts/rc0_candidate/inventories"
        inventory.mkdir(parents=True)
        document = json.loads(INVENTORY.read_text())
        for record in document["records"]:
            if record["id"].startswith("phase3."):
                record.update(
                    selector_status="RESOLVED",
                    fully_qualified_test_name=record["id"].replace(".", "_").replace("-", "_"),
                    list_digest="",
                    toolchain="rustc fixture",
                )
                record["list_digest"] = self._digest_for(record)
        inventory.joinpath("source-candidate-v1.json").write_text(json.dumps(document))

    def _digest_for(self, record: dict[str, str]) -> str:
        import hashlib

        selectors = {
            "evidence_phase3": (
                "phase3_evidence_fixtures", "phase3_evidence_shadow_import",
                "phase3_evidence_lineage", "phase3_evidence_rollback",
            ),
            "migration_control": ("phase3_migration_control",),
            "migration_rollout": ("phase3_migration_rollout",),
            "migration_sqlite": ("phase3_migration_sqlite",),
            "migration_routing_sqlite": ("phase3_migration_routing_sqlite",),
            "migration_routing": ("phase3_migration_routing",),
        }
        names = selectors[record["integration_target"]]
        listing = "".join(f"{name}: test\n" for name in names)
        listing += "\n1 test, 0 benchmarks\n"
        return hashlib.sha256(listing.encode()).hexdigest()

    def _phase3_record_count(self) -> int:
        return sum(record["id"].startswith("phase3.") for record in json.loads(INVENTORY.read_text())["records"])

    def _write_commands(self, root: Path, log: Path) -> None:
        commands = root / "bin"
        commands.mkdir()
        cargo = commands / "cargo"
        cargo.write_text(
            "#!/bin/sh\n"
            f"echo \"$*\" >> '{log}'\n"
            "selector=\"\"; target=\"\"; is_list=false; next_target=false\n"
            "for arg in \"$@\"; do\n"
            "  $next_target && target=\"$arg\" && next_target=false\n"
            "  [ \"$arg\" = \"--test\" ] && next_target=true\n"
            "  [ \"$arg\" = \"--list\" ] && is_list=true\n"
            "  case \"$arg\" in phase3_*) selector=\"$arg\";; esac\n"
            "done\n"
            "if $is_list; then\n"
            "  case \"$target\" in\n"
            "    evidence_phase3) echo phase3_evidence_fixtures: test; echo phase3_evidence_shadow_import: test; echo phase3_evidence_lineage: test; echo phase3_evidence_rollback: test;;\n"
            "    *) echo phase3_$(echo \"$target\" | tr '-' '_'): test;;\n"
            "  esac\n"
            "  echo; echo \"1 test, 0 benchmarks\"\n"
            "else\n"
            "  echo\n  echo \"running 1 test\"\n  echo \"test ${selector} ... ok\"\n  echo\n"
            "  echo \"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\"\n"
            "fi\n"
        )
        cargo.chmod(0o755)
        git = commands / "git"
        git.write_text("#!/bin/sh\necho 0123456789abcdef0123456789abcdef01234567\n")
        git.chmod(0o755)
        rustc = commands / "rustc"
        rustc.write_text("#!/bin/sh\necho 'rustc fixture'\n")
        rustc.chmod(0o755)

    def _run(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "scripts/verify-phase3.sh"],
            cwd=root,
            env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
