"""Executable fixtures for the trusted Desktop qualification workflow code."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-qualification.yml"
ANCHORS = (
    "docs/profiles/desktop-v1-capabilities-v1.json",
    "docs/profiles/desktop-v1-capabilities-v1.digest",
    "docs/evidence/desktop-v1-capability-status-v1.json",
    "docs/schemas/desktop-v1-capabilities-v1.schema.json",
    "contracts/gocode-ui-client-1/bundle.json",
)


def workflow() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def step(job: str, name: str) -> dict[str, object]:
    return next(row for row in workflow()["jobs"][job]["steps"] if row.get("name") == name)


def python_body(job: str, name: str) -> str:
    run = step(job, name)["run"]
    match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", run, re.DOTALL)
    if match is None:
        raise AssertionError(f"missing trusted Python heredoc: {job}/{name}")
    return match.group(1) + "\n"


def run_python(body: str, arguments: list[Path | str], cwd: Path, env: dict[str, str]):
    return subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-", *(str(value) for value in arguments)],
        input=body,
        text=True,
        cwd=cwd,
        env=env,
        capture_output=True,
    )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class QualificationFixture:
    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.base = Path(self._temporary.name)
        self.workspace = self.base / "workspace"
        self.prepared = self.base / "prepared"
        self.signed = self.base / "signed"
        self.workspace.mkdir()
        self.prepared.mkdir()
        for relative in ANCHORS:
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        subprocess.run(["git", "init", "-q"], cwd=self.workspace, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.workspace, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.workspace, check=True)
        subprocess.run(["git", "add", "."], cwd=self.workspace, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.workspace, check=True)
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.workspace, text=True).strip()
        self.env = {
            **os.environ,
            "GITHUB_SHA": self.commit,
            "GITHUB_SERVER_URL": "https://github.example.invalid",
            "GITHUB_REPOSITORY": "octo/gocode",
            "GITHUB_REF": "refs/heads/protected",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY_ID": "101",
            "GITHUB_REPOSITORY_OWNER_ID": "202",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_RUN_ID": "303",
            "GITHUB_RUN_ATTEMPT": "4",
        }
        (self.prepared / "desktop-v1-contract-schema-selectors.txt").write_text("selector\n", encoding="utf-8")
        (self.prepared / "desktop-v1-contract-schema-tests.txt").write_text("tests passed\n", encoding="utf-8")
        metadata = {"candidate_ref": self.commit, "toolchain_identity": {"status": "recorded", "name": "python", "version": "3.13"}}
        (self.prepared / "metadata.json").write_text(json.dumps(metadata, separators=(",", ":")) + "\n", encoding="utf-8")
        self._build()

    def close(self) -> None:
        self._temporary.cleanup()

    def predicate(self) -> dict[str, object]:
        server = self.env["GITHUB_SERVER_URL"]
        repository = self.env["GITHUB_REPOSITORY"]
        ref = self.env["GITHUB_REF"]
        workflow_path = ".github/workflows/desktop-qualification.yml"
        return {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"ref": ref, "repository": f"{server}/{repository}", "path": workflow_path}},
                "internalParameters": {"github": {"event_name": self.env["GITHUB_EVENT_NAME"], "repository_id": self.env["GITHUB_REPOSITORY_ID"], "repository_owner_id": self.env["GITHUB_REPOSITORY_OWNER_ID"], "runner_environment": self.env["RUNNER_ENVIRONMENT"]}},
                "resolvedDependencies": [{"uri": f"git+{server}/{repository}@{ref}", "digest": {"gitCommit": self.commit}}],
            },
            "runDetails": {
                "builder": {"id": f"{server}/{repository}/{workflow_path}@{ref}"},
                "metadata": {"invocationId": f"{server}/{repository}/actions/runs/{self.env['GITHUB_RUN_ID']}/attempts/{self.env['GITHUB_RUN_ATTEMPT']}"},
            },
        }

    def statement(self, subject: Path) -> dict[str, object]:
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": subject.name, "digest": {"sha256": sha(subject)}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": self.predicate(),
        }

    def verification(self, subject: Path) -> list[dict[str, object]]:
        return [{"verificationResult": {"statement": self.statement(subject)}}]

    def _build(self) -> None:
        result = run_python(
            python_body("sign", "Construct bounded gate subject before attestation"),
            [self.workspace, self.prepared, self.signed, self.commit], self.base, self.env,
        )
        if result.returncode:
            raise AssertionError(result.stderr or result.stdout)
        gate = self.signed / "desktop-v1-contract-schema.json"
        self.gate_result = self.base / "gate-final-verification.json"
        self.gate_result.write_text(json.dumps(self.verification(gate)), encoding="utf-8")
        result = run_python(
            python_body("sign", "Verify gate, then construct status from trusted baseline"),
            [self.workspace, self.signed, self.gate_result], self.base, self.env,
        )
        if result.returncode:
            raise AssertionError(result.stderr or result.stdout)
        (self.signed / "desktop-v1-contract-schema.json.intoto.jsonl").write_text("gate bundle\n", encoding="utf-8")
        status = self.signed / "desktop-v1-capability-status-v1.json"
        (self.signed / "desktop-v1-capability-status-v1.json.intoto.jsonl").write_text("status bundle\n", encoding="utf-8")
        result = run_python(
            python_body("sign", "Collect status bundle and close digest manifest"),
            [self.workspace, self.signed], self.base, self.env,
        )
        if result.returncode:
            raise AssertionError(result.stderr or result.stdout)
        self.status_result = self.base / "status-final-verification.json"
        self.status_result.write_text(json.dumps(self.verification(status)), encoding="utf-8")

    def final_verification(self, status_verification=None):
        if status_verification is not None:
            self.status_result.write_text(json.dumps(status_verification), encoding="utf-8")
        return run_python(
            python_body("verify-publish", "Reject malformed package before publication"),
            [self.workspace, self.signed, self.gate_result, self.status_result, self.commit], self.base, self.env,
        )

    def status_verification(self):
        return copy.deepcopy(self.verification(self.signed / "desktop-v1-capability-status-v1.json"))

    def gate_verification(self):
        return copy.deepcopy(self.verification(self.signed / "desktop-v1-contract-schema.json"))

    def gate_to_status_verification(self, gate_verification):
        shutil.copy2(
            self.signed / "desktop-v1-capability-status-baseline.json",
            self.signed / "desktop-v1-capability-status-v1.json",
        )
        self.gate_result.write_text(json.dumps(gate_verification), encoding="utf-8")
        return run_python(
            python_body("sign", "Verify gate, then construct status from trusted baseline"),
            [self.workspace, self.signed, self.gate_result], self.base, self.env,
        )
