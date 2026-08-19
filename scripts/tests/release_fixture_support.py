from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess

from scripts.tests.release_test_support import (
    SUPPORTED_TARGET,
    VERIFY_SCRIPT_PATH,
    bash_native_path,
    run_bash,
)


class VerifyReleaseMixin:
    def package_candidate(self) -> pathlib.Path:
        output = self.root / "output"
        result = self.run_package(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output / f"runne-runtime-1.2.3-{SUPPORTED_TARGET}"

    def run_verify(self, candidate: pathlib.Path, fixture_only: bool = False) -> subprocess.CompletedProcess[str]:
        arguments: list[str] = []
        if fixture_only:
            arguments.append("--fixture-only")
        arguments.extend(["--candidate", bash_native_path(candidate)])
        return run_bash(
            VERIFY_SCRIPT_PATH,
            arguments,
            cwd=self.root,
        )

    def snapshot_tree(self, root: pathlib.Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def verify_json(self, candidate: pathlib.Path, fixture_only: bool = False) -> dict:
        result = self.run_verify(candidate, fixture_only)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def make_approved_candidate(self) -> pathlib.Path:
        candidate = self.package_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        daemon = (candidate / "runne-daemon").read_bytes()
        targets = {"linux": "x86_64-unknown-linux-gnu", "macos": SUPPORTED_TARGET, "windows": "x86_64-pc-windows-msvc"}
        artifact_paths = {"linux": "linux-daemon", "macos": "runne-daemon", "windows": "windows-daemon"}
        for platform, path in artifact_paths.items():
            if path != "runne-daemon":
                (candidate / path).write_bytes(daemon + platform.encode("ascii"))
        artifacts = []
        for platform, path in artifact_paths.items():
            artifacts.append({"kind": "daemon", "path": path, "sha256": hashlib.sha256((candidate / path).read_bytes()).hexdigest(), "target": targets[platform]})
        manifest["artifacts"] = artifacts
        profile_digests = [profile["sha256"] for profile in manifest["profiles"]]
        manifest["platforms"] = [{"artifact_sha256": artifact["sha256"], "os": platform, "profile_digests": profile_digests, "target": targets[platform]} for platform, artifact in zip(artifact_paths, artifacts)]
        for lane in manifest["candidate"]["qualification_lanes"]:
            for slot in lane["hosted_execution_slots"]:
                slot["status"] = "actual"
                slot["hosted_runner"] = {"provider": "fixture-ci", "runner_image": f"{slot['platform']}-image-v1", "run_id": f"{lane['lane_id']}-{slot['platform']}-1"}
        candidate_bytes = json.dumps(manifest["candidate"], sort_keys=True, separators=(",", ":")).encode()
        candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
        evidence_dir = candidate / "evidence"
        evidence_dir.mkdir()
        def write_payload(name: str, payload: dict) -> tuple[str, str]:
            path = evidence_dir / name
            path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            return path.relative_to(candidate).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()
        records = []
        def add(kind: str, platform: str, relative: str, sha256: str, **extra: object) -> None:
            artifact = next(item for item in artifacts if item["target"] == targets[platform])
            record = {"artifact_sha256": artifact["sha256"], "candidate_digest": candidate_digest, "gate_id": kind, "kind": kind, "platform": platform, "profile_digests": profile_digests, "sha256": sha256, "source_revision": manifest["candidate"]["source_revision"], "uri": f"candidate://{candidate.name}/{relative}"}
            record.update(extra)
            records.append(record)
        for platform in targets:
            provenance = {"artifact_sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform]), "candidate_digest": candidate_digest, "profile_digests": profile_digests, "qualification_lanes": manifest["candidate"]["qualification_lanes"], "source_revision": manifest["candidate"]["source_revision"], "target": targets[platform]}
            relative, value = write_payload(f"provenance-{platform}.json", provenance)
            for kind in ("package", "checksums"):
                add(kind, platform, relative, value)
            add("provenance-attestation", platform, relative, value)
        for lane in manifest["candidate"]["qualification_lanes"]:
            for slot in lane["hosted_execution_slots"]:
                relative, value = write_payload(f"hosted-{lane['lane_id']}-{slot['platform']}.json", {"ok": True})
                for kind in ("hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs"):
                    add(kind, slot["platform"], relative, value, cargo_version=lane["cargo_version"], hosted_runner=slot["hosted_runner"], lane_id=lane["lane_id"], rustc_version=lane["rustc_version"])
        compatibility = {"candidate_digest": candidate_digest, "source_revision": manifest["candidate"]["source_revision"], "rows": [{"artifact_sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform]), "candidate_digest": candidate_digest, "disposition": "verified", "platform": platform, "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"]} for platform in targets]}
        relative, value = write_payload("compatibility.json", compatibility)
        add("compatibility", "linux", relative, value)
        supply_chain_payloads = {
            "advisory": {"advisory_database_sha256": "a" * 64, "findings": []},
            "license": {"findings": [], "policy_revision": "fixture-v1"},
            "secret-scan": {"findings": [], "scanner_version": "fixture-v1"},
            "sbom": {"bomFormat": "CycloneDX", "components": [], "specVersion": "1.5"},
            "performance": {"metric_set_sha256": "b" * 64},
            "soak": {"duration_seconds": 60},
            "chaos": {"scenario_set_sha256": "c" * 64},
        }
        for kind, fields in supply_chain_payloads.items():
            if kind == "sbom":
                continue
            payload = {"artifact_sha256": artifacts[0]["sha256"], "candidate_digest": candidate_digest, "outcome": "passed", "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"], **fields}
            supply_relative, supply_value = write_payload(f"{kind}.json", payload)
            add(kind, "linux", supply_relative, supply_value)
        profile_bindings = [
            {"name": profile["name"], "revision": profile["revision"], "sha256": profile["sha256"]}
            for profile in manifest["profiles"]
        ]
        source_candidate_digest = "d" * 64
        source_candidate_revision = "e" * 40
        source_relative, source_value = write_payload(
            "source-candidate.json",
            {
                "artifacts": [
                    {"platform": platform, "sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform])}
                    for platform in targets
                ],
                "candidate_digest": source_candidate_digest,
                "format": "source-candidate-reference.v1",
                "profiles": profile_bindings,
                "source_revision": source_candidate_revision,
            },
        )
        for platform in targets:
            artifact_sha256 = next(item["sha256"] for item in artifacts if item["target"] == targets[platform])
            for kind in ("fresh-install", "upgrade", "rollback"):
                operation_relative, operation_value = write_payload(
                    f"{kind}-{platform}.json",
                    {
                        "candidate_digest": candidate_digest,
                        "destination_artifact_sha256": artifact_sha256,
                        "destination_profiles": profile_bindings,
                        "destination_schema_revision": "release-operation-evidence.v1",
                        "outcome": "passed",
                        "platform": platform,
                        "source_artifact_sha256": artifact_sha256,
                        "source_candidate_digest": source_candidate_digest,
                        "source_candidate_manifest_sha256": source_value,
                        "source_candidate_manifest_uri": f"candidate://{candidate.name}/{source_relative}",
                        "source_candidate_revision": source_candidate_revision,
                        "source_profiles": profile_bindings,
                        "source_revision": manifest["candidate"]["source_revision"],
                        "source_schema_revision": "release-operation-evidence.v1",
                    },
                )
                add(kind, platform, operation_relative, operation_value)
        for platform in targets:
            artifact_sha256 = next(item["sha256"] for item in artifacts if item["target"] == targets[platform])
            sbom_payload = {"artifact_sha256": artifact_sha256, "bomFormat": "CycloneDX", "candidate_digest": candidate_digest, "components": [], "outcome": "passed", "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"], "specVersion": "1.5"}
            relative, value = write_payload(f"sbom-{platform}.json", sbom_payload)
            add("sbom", platform, relative, value)
            phase_payloads = {
                "phase6b-native-certificate": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "containment_outcome": "passed", "native_certificate_sha256": "6" * 64, "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "schema_revision": "phase6b-native-certificate.v1", "source_revision": manifest["candidate"]["source_revision"], "startup_outcome": "passed"},
                "phase8-compatibility": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "compatibility_outcome": "passed", "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "profile_name": profile_bindings[0]["name"], "profile_revision": profile_bindings[0]["revision"], "profile_sha256": profile_bindings[0]["sha256"], "schema_revision": "phase8-compatibility-evidence.v1", "source_revision": manifest["candidate"]["source_revision"]},
                "phase9-operations": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "evaluation_report_sha256": "9" * 64, "observability_report_sha256": "8" * 64, "operations_report_sha256": "7" * 64, "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "schema_revision": "phase9-operations-evidence.v1", "source_revision": manifest["candidate"]["source_revision"]},
            }
            for kind, payload in phase_payloads.items():
                relative, value = write_payload(f"{kind}-{platform}.json", payload)
                add(kind, platform, relative, value)
        manifest["evidence"] = records
        manifest["qualification_state"] = "approved"
        review_subject = {
            "format": manifest["format"], "candidate": manifest["candidate"], "artifacts": manifest["artifacts"],
            "profiles": manifest["profiles"], "platforms": manifest["platforms"], "evidence": records,
        }
        review_subject_digest = hashlib.sha256(json.dumps(review_subject, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        def attestation(kind, payload):
            issuer = "fixture-review-authority"
            identity_key = "owner_identity" if kind == "owner-approval" else "reviewer_identity"
            subject = {"candidate_digest": candidate_digest, "review_subject_digest": review_subject_digest, "kind": kind, "issuer": issuer, "issuer_identity": payload[identity_key], "role": payload["role"], "decision": payload["decision"], "rubric_version": payload["rubric_version"]}
            return {"format": "release-approval-attestation.v1", "issuer": issuer, "subject": subject, "verification": "external-cryptographic-verification-required"}
        review_packet = {"candidate_digest": candidate_digest, "conflict_declaration": "none", "review_subject_digest": review_subject_digest, "reviewer_identity": "reviewer-a", "role": "security", "rubric_version": "v1"}
        final_review = {"candidate_digest": candidate_digest, "conflict_declaration": "none", "decision": "approved", "review_subject_digest": review_subject_digest, "reviewer_identity": "reviewer-b", "role": "security-reliability", "rubric_version": "v1"}
        final_review["attestation"] = attestation("independent-final-review", final_review)
        owner_approval = {"candidate_digest": candidate_digest, "decision": "approved", "owner_identity": "owner-a", "review_subject_digest": review_subject_digest, "role": "owner", "rubric_version": "v1"}
        owner_approval["attestation"] = attestation("owner-approval", owner_approval)
        for kind, payload in (("review-packet", review_packet), ("independent-final-review", final_review), ("owner-approval", owner_approval)):
            relative, value = write_payload(f"{kind}.json", payload)
            add(kind, "linux", relative, value)
        manifest["evidence"] = records
        manifest["qualification_state"] = "approved"
        checksums = []
        for path in sorted((path for path in candidate.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}), key=lambda path: path.relative_to(candidate).as_posix().encode()):
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(candidate).as_posix()}\n")
        (candidate / "checksums.sha256").write_text("".join(checksums), encoding="utf-8")
        (candidate / "release-manifest.v1.json").write_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        return candidate

    def write_manifest(self, candidate: pathlib.Path, manifest: dict) -> None:
        (candidate / "release-manifest.v1.json").write_bytes(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )

    def refresh_candidate(self, candidate: pathlib.Path, manifest: dict, changed_kind: str | None = None) -> None:
        if changed_kind:
            for evidence in manifest["evidence"]:
                if evidence["kind"] == changed_kind:
                    path = candidate / evidence["uri"].split(f"candidate://{candidate.name}/", 1)[1]
                    evidence["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums = []
        for path in sorted((path for path in candidate.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}), key=lambda path: path.relative_to(candidate).as_posix().encode()):
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(candidate).as_posix()}\n")
        (candidate / "checksums.sha256").write_text("".join(checksums), encoding="utf-8")
        self.write_manifest(candidate, manifest)
