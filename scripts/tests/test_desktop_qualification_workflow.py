"""Adversarial regressions for the protected Desktop qualification workflow."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-qualification.yml"
GATE_KEYS = {"schema_version", "kind", "gate_id", "canonical_source_content_sha256", "definition_sha256", "selector_list_sha256", "toolchain_identity", "runner_identity", "artifacts", "tests"}
STATUS_KEYS = {"schema_version", "manifest_id", "definition_sha256", "canonical_source_content_sha256", "recorded_at", "contract", "selector_list_sha256", "toolchain_identity", "runner_identity", "evidence_refs", "platforms", "gates", "capabilities"}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def gate_fixture() -> dict[str, object]:
    artifacts = [{"sha256": char * 64} for char in "abc"]
    return {"schema_version": "desktop-v1-gate-evidence.v1", "kind": "contract", "gate_id": "GATE-CONTRACT-SCHEMA", "canonical_source_content_sha256": "d" * 64, "definition_sha256": "a" * 64, "selector_list_sha256": "e" * 64, "toolchain_identity": {"status": "recorded", "name": "python", "version": "3"}, "runner_identity": {"status": "not_recorded", "runner_id": None, "image_sha256": None}, "artifacts": artifacts, "tests": [{"sha256": "f" * 64}]}


def status_fixture() -> dict[str, object]:
    gate = gate_fixture(); normal = {"gate_id": "GATE-OTHER", "disposition": "not_recorded", "blocker_code": "EVIDENCE_NOT_RECORDED"}
    verified = {"gate_id": gate["gate_id"], "disposition": "verified", "blocker_code": None, "evidence_ref": "gate.json", "provenance": {"subject_sha256": "1" * 64, "predicate_sha256": "2" * 64}}
    return {"schema_version": "desktop-v1-capability-status.v1", "manifest_id": "desktop-v1", "definition_sha256": gate["definition_sha256"], "canonical_source_content_sha256": gate["canonical_source_content_sha256"], "recorded_at": "2026-08-10T00:00:00Z", "contract": {"profile_id": "gocode-ui-client/1", "profile_sha256": "a" * 64, "bundle_sha256": "a" * 64}, "selector_list_sha256": gate["selector_list_sha256"], "toolchain_identity": gate["toolchain_identity"], "runner_identity": gate["runner_identity"], "evidence_refs": [{"id": "gate.json", "sha256": "1" * 64}], "platforms": [{"platform_id": "P", "disposition": "blocked", "blocker_code": "EVIDENCE_NOT_RECORDED"}], "gates": [verified, normal], "capabilities": [{"capability_id": "C", "disposition": "blocked", "blocker_code": "EVIDENCE_NOT_RECORDED"}]}


def closed_gate(value: object, expected: dict[str, object]) -> bool:
    return isinstance(value, dict) and set(value) == GATE_KEYS and value == expected


def closed_status(value: object, expected: dict[str, object]) -> bool:
    return isinstance(value, dict) and set(value) == STATUS_KEYS and value == expected


def closed_statement(value: object, subject_sha: str) -> bool:
    if not isinstance(value, dict) or set(value) != {"_type", "subject", "predicateType", "predicate"} or value["_type"] != "https://in-toto.io/Statement/v1" or value["predicateType"] != "https://slsa.dev/provenance/v1" or not isinstance(value["predicate"], dict) or set(value["predicate"]) != {"buildDefinition", "runDetails"}:
        return False
    rows = value["subject"]
    return isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and set(rows[0]) == {"name", "digest"} and isinstance(rows[0]["name"], str) and set(rows[0]["digest"]) == {"sha256"} and rows[0]["digest"]["sha256"] == subject_sha


def closed_manifest(value: object, expected: list[dict[str, str]]) -> bool:
    return isinstance(value, dict) and set(value) == {"schema_version", "files"} and value.get("schema_version") == "desktop-v1-qualification-package.v1" and value.get("files") == expected and len({row["path"] for row in expected}) == len(expected) and len({row["sha256"] for row in expected}) == len(expected)


class DesktopQualificationWorkflowTests(unittest.TestCase):
    def test_isolated_system_python_rejects_workspace_shadows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"; outside = Path(temporary) / "outside"; workspace.mkdir(); outside.mkdir()
            for name in ("sitecustomize.py", "json.py", "hashlib.py", "pathlib.py"):
                (workspace / name).write_text("from pathlib import Path\nPath(%r).write_text('bad')\n" % str(outside / "marker"), encoding="utf-8")
            environment = {**os.environ, "PYTHONPATH": str(workspace)}
            subprocess.run(["/usr/bin/python3", "-I", "-S", "-"], cwd=outside, env=environment, input="import json, hashlib, pathlib\n", text=True, check=True)
            self.assertFalse((outside / "marker").exists())

    def test_privileged_python_is_isolated_and_precedes_sentinels(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")); text = WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("sign", "verify-publish"):
            steps = workflow["jobs"][job_name]["steps"]
            for step in steps:
                if "run" in step and "python3" in step["run"]:
                    self.assertIn("/usr/bin/python3 -I -S -", step["run"])
                    self.assertEqual(step.get("working-directory"), "${{ runner.temp }}")
            checkout = next(step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@"))
            self.assertEqual(checkout["with"], {"fetch-depth": 0, "persist-credentials": False})
        sign = workflow["jobs"]["sign"]["steps"]
        self.assertLess(next(i for i, step in enumerate(sign) if step.get("name") == "Construct bounded gate subject before attestation"), next(i for i, step in enumerate(sign) if step.get("id") == "gate_attest")); self.assertLess(next(i for i, step in enumerate(sign) if step.get("name") == "Verify gate, then construct status from trusted baseline"), next(i for i, step in enumerate(sign) if step.get("id") == "status_attest"))
        self.assertLess(text.index("Independently verify signed subjects"), text.index("desktop-v1-qualified-status"))

    def test_closed_world_mutations_fail(self) -> None:
        gate = gate_fixture(); status = status_fixture(); subject_sha = "3" * 64
        statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "gate", "digest": {"sha256": subject_sha}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {}, "runDetails": {}}}
        manifest_rows = [{"path": path, "sha256": char * 64} for path, char in (("profile", "a"), ("schema", "b"), ("bundle", "c"), ("test", "d"))]
        self.assertTrue(closed_gate(gate, gate)); self.assertTrue(closed_status(status, status)); self.assertTrue(closed_statement(statement, subject_sha)); self.assertTrue(closed_manifest({"schema_version": "desktop-v1-qualification-package.v1", "files": manifest_rows}, manifest_rows))
        gate_mutations = (lambda x: x.pop("artifacts"), lambda x: x.update(extra=True), lambda x: x.update(kind="wrong"), lambda x: x.update(schema_version="wrong"), lambda x: x["artifacts"].clear(), lambda x: x["artifacts"].append({"sha256": "z" * 64}), lambda x: x.update(artifacts=list(reversed(x["artifacts"]))), lambda x: x.update(artifacts=[{"sha256": "z" * 64}] * 3))
        status_mutations = (lambda x: x["gates"].pop(), lambda x: x["gates"].append(copy.deepcopy(x["gates"][0])), lambda x: x.update(extra=True), lambda x: x["gates"][0].update(extra=True), lambda x: x.update(gates=list(reversed(x["gates"]))))
        statement_mutations = (lambda x: x["subject"].append(copy.deepcopy(x["subject"][0])), lambda x: x.update(predicateType="wrong"), lambda x: x.update(predicate={}), lambda x: x["subject"][0]["digest"].update(sha512="x"))
        manifest_mutations = (lambda x: x["files"].pop(), lambda x: x["files"].append({"path": "extra", "sha256": "e" * 64}), lambda x: x.update(files=[x["files"][0], x["files"][0]]), lambda x: x.update(files=list(reversed(x["files"]))), lambda x: x["files"][1].update(sha256=x["files"][0]["sha256"]))
        for mutations, validator, expected in ((gate_mutations, closed_gate, gate), (status_mutations, closed_status, status), (statement_mutations, closed_statement, subject_sha)):
            for mutation in mutations:
                value = copy.deepcopy(gate if validator is closed_gate else status if validator is closed_status else statement); mutation(value); self.assertFalse(validator(value, expected))
        for mutation in manifest_mutations:
            value = {"schema_version": "desktop-v1-qualification-package.v1", "files": copy.deepcopy(manifest_rows)}; mutation(value); self.assertFalse(closed_manifest(value, manifest_rows))

    def test_branch_and_annotated_tag_bindings(self) -> None:
        def bind(source_ref: str, input_ref: str, head: str, sha: str, protected: str) -> bool:
            return bool(source_ref) and input_ref == head == sha and protected == source_ref
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); subprocess.run(["git", "init", "-q"], cwd=root, check=True); subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True); subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / "fixture").write_text("fixture", encoding="utf-8"); subprocess.run(["git", "add", "fixture"], cwd=root, check=True); subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(); subprocess.run(["git", "branch", "release", sha], cwd=root, check=True); subprocess.run(["git", "tag", "-a", "v1.0.0", "-m", "fixture", sha], cwd=root, check=True)
            for source_ref, ref in (("refs/heads/release", "release"), ("refs/tags/v1.0.0", "v1.0.0")):
                head = subprocess.check_output(["git", "rev-parse", f"{ref}^{{commit}}"], cwd=root, text=True).strip(); self.assertTrue(bind(source_ref, head, head, sha, source_ref))
            self.assertFalse(bind("refs/tags/v1.0.0", sha, "b" * 40, sha, "refs/tags/v1.0.0"))


if __name__ == "__main__":
    unittest.main()
