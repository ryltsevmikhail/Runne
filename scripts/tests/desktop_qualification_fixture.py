"""Execute trusted Desktop qualification workflow commands in a local fixture."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/desktop-qualification.yml"
ANCHORS = (
    "docs/profiles/desktop-v1-capabilities-v1.json",
    "docs/profiles/desktop-v1-capabilities-v1.digest",
    "docs/evidence/desktop-v1-capability-status-baseline-v2.json",
    "docs/evidence/desktop-v1-capability-status-v2.json",
    "docs/schemas/desktop-v1-capability-status-v2.schema.json",
    "contracts/gocode-ui-client-2/bundle.json",
)


def _scalar(value: str):
    value = value.split(" #", 1)[0].strip()
    if value.startswith("{") and value.endswith("}"):
        pairs = (part.strip().split(":", 1) for part in value[1:-1].split(","))
        return {key.strip(): _scalar(item) for key, item in pairs}
    if value in ("true", "false"):
        return value == "true"
    if value.isdigit():
        return int(value)
    return value.strip('"\'')


def workflow(path: Path = WORKFLOW) -> dict[str, object]:
    """Parse only the workflow's literal jobs, steps, mappings, and run blocks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    jobs: dict[str, dict[str, object]] = {}
    job = None
    index = 0
    while index < len(lines):
        job_match = re.fullmatch(r"  ([a-zA-Z0-9_-]+):", lines[index])
        if job_match and index and lines[index - 1].strip() in ("jobs:", ""):
            job = job_match.group(1)
            jobs[job] = {"steps": []}
        step_match = re.fullmatch(r"      - (name|id|uses):\s*(.*)", lines[index])
        if job is None or step_match is None:
            index += 1
            continue
        row: dict[str, object] = {step_match.group(1): _scalar(step_match.group(2))}
        index += 1
        while index < len(lines) and (
            not lines[index].strip() or lines[index].startswith("        ")
        ):
            match = re.fullmatch(r"        ([a-zA-Z0-9_-]+):\s*(.*)", lines[index])
            if match:
                key, value = match.groups()
                if key == "run" and value == "|":
                    index += 1
                    body = []
                    while index < len(lines) and (
                        not lines[index].strip() or lines[index].startswith("          ")
                    ):
                        body.append(lines[index][10:] if lines[index] else "")
                        index += 1
                    row["run"] = "\n".join(body) + "\n"
                    continue
                if value:
                    row[key] = _scalar(value)
            index += 1
        jobs[job]["steps"].append(row)
    return {"jobs": jobs}


def step(job: str, name: str) -> dict[str, object]:
    return next(row for row in workflow()["jobs"][job]["steps"] if row.get("name") == name)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class QualificationFixture:
    def __init__(self, protected_ref: str = "refs/heads/protected"):
        self._temporary = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.base = Path(self._temporary.name)
        self.workspace = self.base / "workspace"
        self.runner = self.base / "runner"
        self.prepared = self.runner / "desktop-v1-prepared"
        self.signed = self.runner / "desktop-v1-signed"
        self.responses = self.base / "responses"
        for directory in (self.workspace, self.runner, self.prepared, self.responses):
            directory.mkdir()
        self._copy_anchors()
        self.commit = self._create_repository(protected_ref)
        self.env = self._environment(protected_ref)
        self._install_gh_stub()
        self._write_prepared_inputs()
        self.executed_steps: list[tuple[str, str]] = []
        self._build()
        self.pristine = self.base / "pristine"
        shutil.copytree(self.signed, self.pristine)

    def close(self) -> None:
        self._temporary.cleanup()

    def _copy_anchors(self) -> None:
        for relative in ANCHORS:
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def _create_repository(self, protected_ref: str) -> str:
        for command in (
            ("git", "init", "-q"),
            ("git", "config", "user.email", "test@example.invalid"),
            ("git", "config", "user.name", "Test"),
            ("git", "add", "."),
            ("git", "commit", "-qm", "fixture"),
        ):
            subprocess.run(command, cwd=self.workspace, check=True)
        commit = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=self.workspace, text=True).strip()
        subprocess.run(("git", "branch", "protected", commit), cwd=self.workspace, check=True)
        subprocess.run(("git", "branch", "alias", commit), cwd=self.workspace, check=True)
        subprocess.run(("git", "tag", "-a", "v1.0.0", "-m", "fixture", commit), cwd=self.workspace, check=True)
        if protected_ref not in ("refs/heads/protected", "refs/tags/v1.0.0"):
            raise ValueError(f"unsupported protected ref: {protected_ref}")
        return commit

    def _environment(self, protected_ref: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.base / 'bin'}:{os.environ['PATH']}",
            "GITHUB_WORKSPACE": str(self.workspace),
            "RUNNER_TEMP": str(self.runner),
            "INPUT_SOURCE_REF": protected_ref,
            "GOCODE_DESKTOP_ATTEST_REPOSITORY": "octo/gocode",
            "GOCODE_DESKTOP_ATTEST_SIGNER_WORKFLOW": "octo/gocode/.github/workflows/desktop-qualification.yml",
            "GOCODE_DESKTOP_ATTEST_SOURCE_REF": protected_ref,
            "GITHUB_SHA": self.commit,
            "GITHUB_SERVER_URL": "https://github.example.invalid",
            "GITHUB_REPOSITORY": "octo/gocode",
            "GITHUB_REF": protected_ref,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY_ID": "101",
            "GITHUB_REPOSITORY_OWNER_ID": "202",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_RUN_ID": "303",
            "GITHUB_RUN_ATTEMPT": "4",
            "GH_TOKEN": "fixture-token",
            "GOCODE_GH_RESPONSES": str(self.responses),
        }

    def _install_gh_stub(self) -> None:
        binary = self.base / "bin" / "gh"
        binary.parent.mkdir()
        binary.write_text(
            """#!/bin/sh
set -eu
[ "$#" -eq 18 ] && [ "$1" = attestation ] && [ "$2" = verify ] || exit 41
subject="$3"; shift 3
[ "$1" = --bundle ] && [ -f "$2" ] && [ "$3" = --repo ] && [ "$4" = "$GOCODE_DESKTOP_ATTEST_REPOSITORY" ] || exit 42
[ "$5" = --signer-workflow ] && [ "$6" = "$GOCODE_DESKTOP_ATTEST_SIGNER_WORKFLOW" ] || exit 43
[ "$7" = --source-ref ] && [ "$8" = "$GOCODE_DESKTOP_ATTEST_SOURCE_REF" ] || exit 44
[ "$9" = --source-digest ] && [ "${10}" = "$GITHUB_SHA" ] || exit 45
[ "${11}" = --predicate-type ] && [ "${12}" = https://slsa.dev/provenance/v1 ] || exit 46
[ "${13}" = --no-public-good ] && [ "${14}" = --format ] && [ "${15}" = json ] || exit 47
response="$GOCODE_GH_RESPONSES/${subject##*/}.verification.json"
[ -f "$response" ] || exit 48
exec /bin/cat "$response"
""",
            encoding="utf-8",
        )
        binary.chmod(0o755)

    def _write_prepared_inputs(self) -> None:
        (self.prepared / "desktop-v1-contract-schema-selectors.txt").write_text("selector\n", encoding="utf-8")
        (self.prepared / "desktop-v1-contract-schema-tests.txt").write_text("tests passed\n", encoding="utf-8")
        metadata = {"candidate_ref": self.commit, "toolchain_identity": {"status": "recorded", "name": "python", "version": "3.13"}}
        (self.prepared / "metadata.json").write_text(json.dumps(metadata, separators=(",", ":")) + "\n", encoding="utf-8")

    def _command(self, job: str, name: str, env: dict[str, str] | None = None):
        row = step(job, name)
        command = row["run"]
        substitutions = {
            "${{ steps.gate_attest.outputs.bundle-path }}": str(self.runner / "gate-action-bundle.jsonl"),
            "${{ steps.status_attest.outputs.bundle-path }}": str(self.runner / "status-action-bundle.jsonl"),
        }
        for expression, value in substitutions.items():
            command = command.replace(expression, value)
        if "${{" in command:
            raise AssertionError(f"unresolved workflow expression in {job}/{name}")
        cwd = self.runner if row.get("working-directory") == "${{ runner.temp }}" else self.workspace
        self.executed_steps.append((job, name))
        return subprocess.run(("bash", "-c", command), cwd=cwd, env=env or self.env, capture_output=True, text=True)

    def _require(self, job: str, name: str, env: dict[str, str] | None = None) -> None:
        result = self._command(job, name, env)
        if result.returncode:
            raise AssertionError(result.stderr or result.stdout)

    def predicate(self) -> dict[str, object]:
        server, repository, ref = (self.env[key] for key in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_REF"))
        workflow_path = ".github/workflows/desktop-qualification.yml"
        return {"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"ref":ref,"repository":f"{server}/{repository}","path":workflow_path}},"internalParameters":{"github":{"event_name":self.env["GITHUB_EVENT_NAME"],"repository_id":self.env["GITHUB_REPOSITORY_ID"],"repository_owner_id":self.env["GITHUB_REPOSITORY_OWNER_ID"],"runner_environment":self.env["RUNNER_ENVIRONMENT"]}},"resolvedDependencies":[{"uri":f"git+{server}/{repository}@{ref}","digest":{"gitCommit":self.commit}}]},"runDetails":{"builder":{"id":f"{server}/{repository}/{workflow_path}@{ref}"},"metadata":{"invocationId":f"{server}/{repository}/actions/runs/{self.env['GITHUB_RUN_ID']}/attempts/{self.env['GITHUB_RUN_ATTEMPT']}"}}}

    def verification(self, subject: Path) -> list[dict[str, object]]:
        statement = {"_type":"https://in-toto.io/Statement/v1","subject":[{"name":subject.name,"digest":{"sha256":sha(subject)}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":self.predicate()}
        return [{"verificationResult": {"statement": statement}}]

    def _response(self, subject: Path, value=None) -> None:
        data = self.verification(subject) if value is None else value
        (self.responses / f"{subject.name}.verification.json").write_text(json.dumps(data), encoding="utf-8")

    def _build(self) -> None:
        self._require("prepare", "Bind input before executing candidate code")
        self._require("sign", "Construct bounded gate subject before attestation")
        gate = self.signed / "desktop-v1-contract-schema.json"
        (self.runner / "gate-action-bundle.jsonl").write_text("gate action bundle\n", encoding="utf-8")
        self._response(gate)
        self._require("sign", "Verify gate, then construct status from trusted baseline")
        status = self.signed / "desktop-v1-capability-status-v2.json"
        (self.runner / "status-action-bundle.jsonl").write_text("status action bundle\n", encoding="utf-8")
        self._require("sign", "Collect status bundle and close digest manifest")
        self._response(status)
        self._require("verify-publish", "Bind protected policy and event checkout")
        self._require("verify-publish", "Independently verify signed subjects")

    def final_verification(self, status_verification=None):
        if status_verification is not None:
            self._response(self.signed / "desktop-v1-capability-status-v2.json", status_verification)
        verified = self._command("verify-publish", "Independently verify signed subjects")
        return verified if verified.returncode else self._command("verify-publish", "Reject malformed package before publication")

    def status_verification(self):
        return copy.deepcopy(self.verification(self.signed / "desktop-v1-capability-status-v2.json"))

    def gate_verification(self):
        return copy.deepcopy(self.verification(self.signed / "desktop-v1-contract-schema.json"))

    def gate_to_status_verification(self, gate_verification):
        shutil.copy2(self.signed / "desktop-v1-capability-status-baseline.json", self.signed / "desktop-v1-capability-status-v2.json")
        self._response(self.signed / "desktop-v1-contract-schema.json", gate_verification)
        return self._command("sign", "Verify gate, then construct status from trusted baseline")

    def restore_package(self) -> None:
        for path in self.signed.iterdir():
            path.unlink()
        for path in self.pristine.iterdir():
            shutil.copy2(path, self.signed / path.name)
        self._response(self.signed / "desktop-v1-contract-schema.json")
        self._response(self.signed / "desktop-v1-capability-status-v2.json")

    def mutate_json(self, name: str, mutate) -> None:
        path = self.signed / name
        value = json.loads(path.read_bytes())
        mutate(value)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def authenticate_and_reclose(self) -> None:
        self._response(self.signed / "desktop-v1-contract-schema.json")
        self._response(self.signed / "desktop-v1-capability-status-v2.json")
        manifest = self.signed / "desktop-v1-package-manifest.json"
        value = json.loads(manifest.read_bytes())
        for row in value["files"]:
            row["sha256"] = sha(self.signed / row["path"])
        manifest.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def publication_attempt(self):
        sentinel = self.base / "upload-sentinel"
        sentinel.unlink(missing_ok=True)
        result = self.final_verification()
        if result.returncode == 0:
            sentinel.write_text("uploaded\n", encoding="utf-8")
        return result, sentinel

    def binding_attempt(self, job: str, name: str, env: dict[str, str]):
        if job != "sign":
            return self._command(job, name, env)
        backup = self.base / "signed-backup"
        self.signed.rename(backup)
        try:
            return self._command(job, name, env)
        finally:
            if self.signed.exists():
                shutil.rmtree(self.signed)
            backup.rename(self.signed)
