#!/usr/bin/env python3
"""Offline schema reference for the SourceCraft native evidence enforcer.

The qualification workflow invokes the runner-owned wrapper at
``/opt/gocode/sourcecraft/bin/sourcecraft-native-package-evidence-enforce``;
this candidate-checkout module is never an active trust boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .capability_manifest_impl.io import SOURCECRAFT_ATTEST_VERIFIER_PATH
    from .native_package_probe import NON_APPLICABLE_OPERATIONS, OPERATIONS, artifact_sha256
else:
    from capability_manifest_impl.io import SOURCECRAFT_ATTEST_VERIFIER_PATH
    from native_package_probe import NON_APPLICABLE_OPERATIONS, OPERATIONS, artifact_sha256

SCHEMA = "desktop-native-platform-foundation.v1"
EXPECTED_REPOSITORY = "https://git@git.sourcecraft.dev/ryltsevmg/runne.git"
EXPECTED_WORKFLOW = "desktop-qualification"
EXPECTED_SOURCE_REF = "refs/tags/v1.0.0"


def _sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate(value: object, *, source_digest: str | None = None, job_id: str | None = None,
             workflow_run_id: str | None = None, package_digest: str | None = None) -> list[str]:
    if not isinstance(value, dict):
        return ["evidence must be a JSON object"]
    errors: list[str] = []
    if value.get("schema_version") != SCHEMA:
        errors.append("invalid evidence schema")
    if value.get("disposition") != "verified":
        errors.append("disposition is not verified")
    if "blocker_code" not in value or value.get("blocker_code") is not None:
        errors.append("blocker_code is present")
    if value.get("package_present") is not True:
        errors.append("package_present is not true")
    operations = value.get("native_operations")
    if not isinstance(operations, dict) or set(operations) != set(OPERATIONS):
        errors.append("native_operations does not match the complete operation set")
    elif any(
        not isinstance(result, dict)
        or result.get("status")
        not in ("verified", "not_applicable")
        or (operation in NON_APPLICABLE_OPERATIONS.get(str(value.get("platform_id")), frozenset()) and result.get("status") not in ("verified", "not_applicable"))
        or (operation not in NON_APPLICABLE_OPERATIONS.get(str(value.get("platform_id")), frozenset()) and result.get("status") != "verified")
        for operation, result in operations.items()
    ):
        errors.append("native operation is not verified")
    if not _sha(value.get("artifact_sha256")):
        errors.append("artifact_sha256 is missing or invalid")
    elif package_digest is not None and value["artifact_sha256"] != package_digest:
        errors.append("artifact_sha256 does not match the admitted package")
    if source_digest is not None and value.get("source_ref") != source_digest:
        errors.append("source_ref does not match the SourceCraft commit")
    runner = value.get("runner")
    if not isinstance(runner, dict):
        errors.append("runner admission is missing")
    else:
        for key in ("instance_id", "job_id", "workflow_run_id"):
            if not isinstance(runner.get(key), str) or not runner[key]:
                errors.append(f"runner.{key} is missing")
        for key in ("image_sha256", "boot_measurement_sha256", "admission_sha256"):
            if not _sha(runner.get(key)):
                errors.append(f"runner.{key} is missing or invalid")
        if job_id is not None and runner.get("job_id") != job_id:
            errors.append("runner.job_id does not match SourceCraft task")
        if workflow_run_id is not None and runner.get("workflow_run_id") != workflow_run_id:
            errors.append("runner.workflow_run_id does not match SourceCraft run")
    return errors


def _external_proof(evidence: Path, bundle: Path, args: argparse.Namespace) -> tuple[dict[str, object] | None, str | None]:
    verifier = SOURCECRAFT_ATTEST_VERIFIER_PATH
    if not verifier.is_file() or not os.access(verifier, os.X_OK):
        return None, "fixed SourceCraft verifier is unavailable"
    command = [str(verifier), "verify", "--subject", str(evidence), "--bundle", str(bundle),
               "--repository", args.repository, "--workflow", args.workflow,
               "--source-ref", args.source_ref, "--source-digest", args.source_digest,
               "--job-id", args.job_id, "--workflow-run-id", args.workflow_run_id,
               "--format", "json"]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        value = json.loads(result.stdout) if result.returncode == 0 else None
    except (FileNotFoundError, OSError, json.JSONDecodeError) as error:
        return None, f"external SourceCraft verification failed: {error}"
    if not isinstance(value, dict) or set(value) != {"verified", "subject_sha256", "predicate"}:
        return None, "external verifier returned an invalid result"
    if value.get("verified") is not True or value.get("subject_sha256") != hashlib.sha256(evidence.read_bytes()).hexdigest():
        return None, "external verifier did not verify the evidence subject"
    predicate = value.get("predicate")
    if not isinstance(predicate, dict):
        return None, "external verifier predicate is missing"
    required = {"repository", "workflow", "source_ref", "source_digest", "job_id", "workflow_run_id", "artifact_sha256", "runner"}
    if set(predicate) != required:
        return None, "external predicate does not bind repository, source, job, run, artifact, and runner"
    expected = {"repository": args.repository, "workflow": args.workflow, "source_ref": args.source_ref,
                "source_digest": args.source_digest, "job_id": args.job_id, "workflow_run_id": args.workflow_run_id}
    if any(predicate.get(key) != expected[key] for key in expected):
        return None, "external predicate binding does not match SourceCraft context"
    if not _sha(predicate.get("artifact_sha256")):
        return None, "external predicate artifact digest is invalid"
    if not isinstance(predicate.get("runner"), dict):
        return None, "external predicate runner admission is missing"
    return predicate, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repository", default=os.environ.get("SOURCECRAFT_REPO_URL", ""))
    parser.add_argument("--workflow", default=os.environ.get("SOURCECRAFT_WORKFLOW", ""))
    parser.add_argument("--source-ref", default=os.environ.get("SOURCECRAFT_COMMIT_REF", ""))
    parser.add_argument("--source-digest", default=os.environ.get("SOURCECRAFT_COMMIT_SHA", ""))
    parser.add_argument("--job-id", default=os.environ.get("SOURCECRAFT_TASK", ""))
    parser.add_argument("--workflow-run-id", default=os.environ.get("SOURCECRAFT_RUN_ID", ""))
    args = parser.parse_args(argv)
    try:
        value = json.loads(args.evidence.read_text(encoding="utf-8"))
        package_digest = artifact_sha256(args.package)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"verified": False, "errors": [f"invalid evidence or package: {error}"]}, sort_keys=True))
        return 1
    errors = validate(value, source_digest=args.source_digest, job_id=args.job_id,
                      workflow_run_id=args.workflow_run_id, package_digest=package_digest)
    if args.repository != EXPECTED_REPOSITORY:
        errors.append("repository is not the protected SourceCraft repository")
    if args.workflow != EXPECTED_WORKFLOW:
        errors.append("workflow is not the protected desktop qualification workflow")
    if args.source_ref != EXPECTED_SOURCE_REF:
        errors.append("source-ref is not the protected v1.0.0 tag")
    if not args.repository or not args.workflow or not args.source_ref or not args.source_digest or not args.job_id or not args.workflow_run_id:
        errors.append("SourceCraft repository, workflow, source, job, and run bindings are required")
    if not args.bundle.is_file():
        errors.append("SourceCraft attestation bundle is unavailable")
    else:
        predicate, proof_error = _external_proof(args.evidence, args.bundle, args)
        if proof_error:
            errors.append(proof_error)
        elif predicate is not None:
            if predicate["artifact_sha256"] != package_digest or predicate["artifact_sha256"] != value.get("artifact_sha256"):
                errors.append("external artifact digest does not match evidence and package")
            if predicate["runner"] != value.get("runner"):
                errors.append("external runner admission does not match evidence")
    print(json.dumps({"verified": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
