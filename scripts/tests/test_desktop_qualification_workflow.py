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
    def test_fixture_is_stdlib_only_and_executes_complete_run_blocks(self) -> None:
        result = subprocess.run(
            ["/usr/bin/python3", "-S", "-c", "from scripts.tests.desktop_qualification_fixture import workflow; assert len(workflow()['jobs']) == 3"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_ci_runs_posix_workflow_test_only_on_linux(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        marker = "python3 -m unittest scripts.tests.test_desktop_qualification_workflow -v"
        self.assertEqual(ci.count(marker), 1)
        step_start = ci.rfind("      - name:", 0, ci.index(marker))
        step = ci[step_start : ci.find("\n      - name:", ci.index(marker))]
        self.assertIn("if: matrix.mode == 'pinned' && runner.os == 'Linux'", step)
        manifest = "python3 -m unittest scripts.tests.test_desktop_capability_manifest -v"
        manifest_start = ci.rfind("      - name:", 0, ci.index(manifest))
        manifest_step = ci[manifest_start : ci.find("\n      - name:", ci.index(manifest))]
        self.assertIn("if: matrix.mode == 'pinned'", manifest_step)
        self.assertNotIn("runner.os", manifest_step)
        for path in (".github/workflows/desktop-ci.yml", ".github/workflows/desktop-qualification.yml", "scripts/ci-local.sh"):
            self.assertIn(marker, (ROOT / path).read_text(encoding="utf-8"), path)

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
                if "run" in row:
                    self.assertEqual(row.get("working-directory"), "${{ runner.temp }}")
                    if "python3" in row["run"]:
                        self.assertIn("/usr/bin/python3 -I -S -", row["run"])
            checkout = next(row for row in steps if str(row.get("uses", "")).startswith("actions/checkout@"))
            self.assertEqual(checkout["with"], {"fetch-depth": 0, "persist-credentials": False})
        sign = data["jobs"]["sign"]["steps"]
        self.assertEqual(next(row for row in sign if row.get("id") == "gate_attest")["with"], {"subject-path": "${{ runner.temp }}/desktop-v1-signed/desktop-v1-contract-schema.json"})
        self.assertEqual(next(row for row in sign if row.get("id") == "status_attest")["with"], {"subject-path": "${{ runner.temp }}/desktop-v1-signed/desktop-v1-capability-status-v1.json"})
        self.assertLess(next(i for i, row in enumerate(sign) if row.get("name") == "Construct bounded gate subject before attestation"), next(i for i, row in enumerate(sign) if row.get("id") == "gate_attest"))
        self.assertLess(next(i for i, row in enumerate(sign) if row.get("name") == "Verify gate, then construct status from trusted baseline"), next(i for i, row in enumerate(sign) if row.get("id") == "status_attest"))
        publish = data["jobs"]["verify-publish"]["steps"]
        self.assertLess(next(i for i, row in enumerate(publish) if row.get("name") == "Reject malformed package before publication"), next(i for i, row in enumerate(publish) if str(row.get("uses", "")).startswith("actions/upload-artifact@")))

    def test_exact_final_verifier_accepts_pinned_action_statement(self) -> None:
        fixture = QualificationFixture()
        self.addCleanup(fixture.close)
        result = fixture.final_verification()
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        required = {
            ("prepare", "Bind input before executing candidate code"),
            ("sign", "Construct bounded gate subject before attestation"),
            ("sign", "Verify gate, then construct status from trusted baseline"),
            ("sign", "Collect status bundle and close digest manifest"),
            ("verify-publish", "Bind protected policy and event checkout"),
            ("verify-publish", "Independently verify signed subjects"),
            ("verify-publish", "Reject malformed package before publication"),
        }
        self.assertTrue(required.issubset(fixture.executed_steps))

    def _reject_package_mutations(self, name, mutations, reclose=True) -> None:
        fixture = QualificationFixture()
        self.addCleanup(fixture.close)
        for label, mutate in mutations.items():
            with self.subTest(file=name, label=label):
                fixture.restore_package()
                fixture.mutate_json(name, mutate)
                if reclose:
                    fixture.authenticate_and_reclose()
                result, sentinel = fixture.publication_attempt()
                self.assertNotEqual(result.returncode, 0, label)
                self.assertFalse(sentinel.exists(), label)

    def test_exact_final_verifier_rejects_gate_shape_and_binding_mutations(self) -> None:
        mutations = {
            "wrong schema": lambda x: x.update(schema_version="wrong"),
            "wrong kind": lambda x: x.update(kind="platform"),
            "root extra": lambda x: x.update(extra=True),
            "artifact row extra": lambda x: x["artifacts"][0].update(extra=True),
            "empty artifacts": lambda x: x.update(artifacts=[]),
            "extra artifacts": lambda x: x["artifacts"].append(copy.deepcopy(x["artifacts"][0])),
            "reordered artifacts": lambda x: x["artifacts"].reverse(),
            "misbound artifact": lambda x: x["artifacts"][0].update(sha256="0" * 64),
            "empty tests": lambda x: x.update(tests=[]),
            "extra tests": lambda x: x["tests"].append(copy.deepcopy(x["tests"][0])),
            "extra reordered tests": lambda x: x.update(tests=[{"sha256": "0" * 64}, copy.deepcopy(x["tests"][0])]),
            "test row extra": lambda x: x["tests"][0].update(extra=True),
            "misbound test": lambda x: x["tests"][0].update(sha256="0" * 64),
        }
        self._reject_package_mutations("desktop-v1-contract-schema.json", mutations)

    def test_exact_final_verifier_rejects_status_gate_mutations(self) -> None:
        mutations = {
            "wrong schema": lambda x: x.update(schema_version="wrong"),
            "root extra": lambda x: x.update(extra=True),
            "missing gate": lambda x: x["gates"].pop(),
            "extra gate": lambda x: x["gates"].append(copy.deepcopy(x["gates"][-1])),
            "reordered gates": lambda x: x["gates"].reverse(),
            "gate row extra": lambda x: x["gates"][1].update(extra=True),
            "misbound gate": lambda x: x["gates"][1].update(gate_id="GATE-WRONG"),
        }
        self._reject_package_mutations("desktop-v1-capability-status-v1.json", mutations)

    def test_exact_final_verifier_rejects_manifest_closed_world_mutations(self) -> None:
        mutations = {
            "wrong schema": lambda x: x.update(schema_version="wrong"),
            "root extra": lambda x: x.update(extra=True),
            "row extra": lambda x: x["files"][0].update(extra=True),
            "missing path": lambda x: x["files"].pop(),
            "extra path": lambda x: x["files"].append({"path": "extra", "sha256": "0" * 64}),
            "duplicate path": lambda x: x["files"].append(copy.deepcopy(x["files"][0])),
            "reordered paths": lambda x: x["files"].reverse(),
            "wrong digest": lambda x: x["files"][0].update(sha256="0" * 64),
            "digest alias": lambda x: x["files"][1].update(sha256=x["files"][0]["sha256"]),
        }
        self._reject_package_mutations("desktop-v1-package-manifest.json", mutations, reclose=False)

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
        binding_steps = (
            ("prepare", "Bind input before executing candidate code"),
            ("sign", "Construct bounded gate subject before attestation"),
            ("verify-publish", "Bind protected policy and event checkout"),
        )
        for protected_ref in ("refs/heads/protected", "refs/tags/v1.0.0"):
            fixture = QualificationFixture(protected_ref)
            self.addCleanup(fixture.close)
            for binding in binding_steps:
                self.assertIn(binding, fixture.executed_steps)
                alias = {**fixture.env, "INPUT_SOURCE_REF": "refs/heads/alias"}
                result = fixture.binding_attempt(*binding, env=alias)
                self.assertNotEqual(result.returncode, 0, f"{binding} accepted alias ref")


if __name__ == "__main__":
    unittest.main()
