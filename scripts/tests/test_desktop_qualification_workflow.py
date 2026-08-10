"""Executable adversarial regressions for Desktop qualification."""

import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.tests.desktop_qualification_fixture import (
    QualificationFixture,
    ROOT,
    step,
    workflow,
)


class DesktopQualificationWorkflowTests(unittest.TestCase):
    def test_isolated_system_python_rejects_workspace_shadows(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as temporary:
            workspace = Path(temporary) / "workspace"
            outside = Path(temporary) / "outside"
            workspace.mkdir()
            outside.mkdir()
            for name in ("sitecustomize.py", "json.py", "hashlib.py", "pathlib.py"):
                (workspace / name).write_text("from pathlib import Path\nPath(%r).write_text('bad')\n" % str(outside / "marker"), encoding="utf-8")
            environment = {**os.environ, "PYTHONPATH": str(workspace)}
            subprocess.run(["/usr/bin/python3", "-I", "-S", "-"], cwd=outside, env=environment, input="import json, hashlib, pathlib\n", text=True, check=True)
            self.assertFalse((outside / "marker").exists())

    def test_privileged_ordering_and_isolated_interpreters(self) -> None:
        data = workflow()
        for job_name in ("sign", "verify-publish"):
            steps = data["jobs"][job_name]["steps"]
            for row in steps:
                if "run" in row and "python3" in row["run"]:
                    self.assertIn("/usr/bin/python3 -I -S -", row["run"])
                    self.assertEqual(row.get("working-directory"), "${{ runner.temp }}")
            checkout = next(row for row in steps if str(row.get("uses", "")).startswith("actions/checkout@"))
            self.assertEqual(checkout["with"], {"fetch-depth": 0, "persist-credentials": False})
        sign = data["jobs"]["sign"]["steps"]
        self.assertLess(next(i for i, row in enumerate(sign) if row.get("name") == "Construct bounded gate subject before attestation"), next(i for i, row in enumerate(sign) if row.get("id") == "gate_attest"))
        self.assertLess(next(i for i, row in enumerate(sign) if row.get("name") == "Verify gate, then construct status from trusted baseline"), next(i for i, row in enumerate(sign) if row.get("id") == "status_attest"))
        publish = data["jobs"]["verify-publish"]["steps"]
        self.assertLess(next(i for i, row in enumerate(publish) if row.get("name") == "Reject malformed package before publication"), next(i for i, row in enumerate(publish) if str(row.get("uses", "")).startswith("actions/upload-artifact@")))

    def test_exact_final_verifier_accepts_pinned_action_statement(self) -> None:
        fixture = QualificationFixture()
        self.addCleanup(fixture.close)
        result = fixture.final_verification()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_exact_final_verifier_rejects_nested_slsa_mutations_before_upload(self) -> None:
        fixture = QualificationFixture()
        self.addCleanup(fixture.close)
        original = fixture.status_verification()
        valid = fixture.final_verification(original)
        self.assertEqual(valid.returncode, 0, valid.stderr or valid.stdout)

        def statement(value):
            return value[0]["verificationResult"]["statement"]

        mutations = {
            "wrong statement type": lambda x: statement(x).update(_type="wrong"),
            "wrong predicate type": lambda x: statement(x).update(predicateType="wrong"),
            "empty predicate": lambda x: statement(x).update(predicate={}),
            "extra predicate field": lambda x: statement(x)["predicate"].update(extra=True),
            "missing buildType": lambda x: statement(x)["predicate"]["buildDefinition"].pop("buildType"),
            "wrong buildType": lambda x: statement(x)["predicate"]["buildDefinition"].update(buildType="wrong"),
            "empty buildDefinition": lambda x: statement(x)["predicate"].update(buildDefinition={}),
            "wrong workflow repository": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(repository="https://example.invalid/other/repo"),
            "wrong workflow ref": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(ref="refs/heads/other"),
            "leading-slash workflow path": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(path="/.github/workflows/desktop-qualification.yml"),
            "empty workflow": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"].update(workflow={}),
            "extra workflow field": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(extra=True),
            "wrong source commit": lambda x: statement(x)["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"].update(gitCommit="0" * 40),
            "wrong source URI": lambda x: statement(x)["predicate"]["buildDefinition"]["resolvedDependencies"][0].update(uri="git+https://example.invalid/other/repo@refs/heads/other"),
            "empty dependency": lambda x: statement(x)["predicate"]["buildDefinition"].update(resolvedDependencies=[{}]),
            "multiple dependencies": lambda x: statement(x)["predicate"]["buildDefinition"]["resolvedDependencies"].append(copy.deepcopy(statement(x)["predicate"]["buildDefinition"]["resolvedDependencies"][0])),
            "wrong builder": lambda x: statement(x)["predicate"]["runDetails"]["builder"].update(id="https://example.invalid/builder"),
            "empty builder": lambda x: statement(x)["predicate"]["runDetails"].update(builder={}),
            "wrong invocation": lambda x: statement(x)["predicate"]["runDetails"]["metadata"].update(invocationId="https://example.invalid/run"),
            "empty metadata": lambda x: statement(x)["predicate"]["runDetails"].update(metadata={}),
            "extra runDetails": lambda x: statement(x)["predicate"]["runDetails"].update(extra=True),
            "empty internal parameters": lambda x: statement(x)["predicate"]["buildDefinition"].update(internalParameters={}),
            "wrong repository id": lambda x: statement(x)["predicate"]["buildDefinition"]["internalParameters"]["github"].update(repository_id="wrong"),
            "extra internal parameter": lambda x: statement(x)["predicate"]["buildDefinition"]["internalParameters"]["github"].update(extra=True),
            "wrong subject name": lambda x: statement(x)["subject"][0].update(name="other.json"),
            "wrong subject digest": lambda x: statement(x)["subject"][0].update(digest={"sha256": "0" * 64}),
            "multiple subjects": lambda x: statement(x)["subject"].append(copy.deepcopy(statement(x)["subject"][0])),
            "extra subject field": lambda x: statement(x)["subject"][0].update(extra=True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                value = copy.deepcopy(original)
                mutate(value)
                sentinel = fixture.base / "upload-sentinel"
                result = fixture.final_verification(value)
                if result.returncode == 0:
                    sentinel.write_text("uploaded", encoding="utf-8")
                self.assertNotEqual(result.returncode, 0, label)
                self.assertFalse(sentinel.exists(), label)

    def test_exact_signer_verifier_rejects_nested_mutations_before_status_attest(self) -> None:
        fixture = QualificationFixture()
        self.addCleanup(fixture.close)
        original = fixture.gate_verification()
        valid = fixture.gate_to_status_verification(original)
        self.assertEqual(valid.returncode, 0, valid.stderr or valid.stdout)

        def statement(value):
            return value[0]["verificationResult"]["statement"]

        mutations = {
            "missing build type": lambda x: statement(x)["predicate"]["buildDefinition"].pop("buildType"),
            "misbound repository": lambda x: statement(x)["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(repository="https://example.invalid/other"),
            "misbound builder": lambda x: statement(x)["predicate"]["runDetails"]["builder"].update(id="https://example.invalid/builder"),
            "misbound invocation": lambda x: statement(x)["predicate"]["runDetails"]["metadata"].update(invocationId="https://example.invalid/run"),
            "wrong subject name": lambda x: statement(x)["subject"][0].update(name="other.json"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                value = copy.deepcopy(original)
                mutate(value)
                sentinel = fixture.base / "status-attest-sentinel"
                result = fixture.gate_to_status_verification(value)
                if result.returncode == 0:
                    sentinel.write_text("attested", encoding="utf-8")
                self.assertNotEqual(result.returncode, 0, label)
                self.assertFalse(sentinel.exists(), label)

    def test_branch_and_annotated_tag_use_exact_ref_binding_commands(self) -> None:
        prepare_run = step("prepare", "Bind input before executing candidate code")["run"]
        protected_run = step("verify-publish", "Bind protected policy and event checkout")["run"]
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as temporary:
            repository = Path(temporary) / "repository"
            runner = Path(temporary) / "runner"
            repository.mkdir()
            runner.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
            (repository / "fixture").write_text("fixture", encoding="utf-8")
            subprocess.run(["git", "add", "fixture"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repository, check=True)
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
            subprocess.run(["git", "branch", "release", commit], cwd=repository, check=True)
            subprocess.run(["git", "branch", "alias", commit], cwd=repository, check=True)
            subprocess.run(["git", "tag", "-a", "v1.0.0", "-m", "fixture", commit], cwd=repository, check=True)
            for protected_ref in ("refs/heads/release", "refs/tags/v1.0.0"):
                environment = {
                    **os.environ,
                    "GITHUB_WORKSPACE": str(repository),
                    "GITHUB_SHA": commit,
                    "GITHUB_REF": protected_ref,
                    "INPUT_SOURCE_REF": protected_ref,
                    "GITHUB_REPOSITORY": "octo/gocode",
                    "GOCODE_DESKTOP_ATTEST_REPOSITORY": "octo/gocode",
                    "GOCODE_DESKTOP_ATTEST_SOURCE_REF": protected_ref,
                    "GOCODE_DESKTOP_ATTEST_SIGNER_WORKFLOW": "octo/gocode/.github/workflows/desktop-qualification.yml",
                }
                result = subprocess.run(["bash", "-c", prepare_run], cwd=repository, env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(["bash", "-c", protected_run], cwd=runner, env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                alias = {**environment, "INPUT_SOURCE_REF": "refs/heads/alias"}
                result = subprocess.run(["bash", "-c", prepare_run], cwd=repository, env=alias, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, "prepare accepted the same commit under a different input ref")
                result = subprocess.run(["bash", "-c", protected_run], cwd=runner, env=alias, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, "same commit under a different input ref must fail")


if __name__ == "__main__":
    unittest.main()
