#!/usr/bin/env python3
"""Validate recorded Desktop performance measurements against release budgets."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path

try:
    from scripts.desktop.capability_manifest_impl.io import load_json, protected_policy, verify_attestation
except ModuleNotFoundError:
    from capability_manifest_impl.io import load_json, protected_policy, verify_attestation


METRICS = {
    "shell_p75": ("ms", "maximum", 1500),
    "navigation_p95": ("ms", "maximum", 100),
    "event_to_render_p95": ("ms", "maximum", 50),
    "timeline_fps": ("fps", "minimum", 55),
    "renderer_idle_memory": ("MiB", "maximum", 250),
    "timeline_10k_memory": ("MiB", "maximum", 500),
    "compressed_js": ("MiB", "maximum", 2),
    "critical_flow_long_task": ("ms", "maximum", 100),
}
CANONICAL_MEASUREMENTS = Path("docs/evidence/desktop-qualification/desktop-performance-measurements.json")
SOURCE_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+")
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")


def _metrics_digest(metrics: dict[str, object]) -> str:
    encoded = json.dumps(metrics, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_measurements(
    path: Path,
    *,
    source_ref: str,
    source_digest: str,
    verify_external: bool = False,
    bundle: Path | None = None,
    root: Path | None = None,
    policy: dict[str, str] | None = None,
) -> list[str]:
    try:
        value = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return ["measurements: invalid JSON"]
    if not isinstance(value, dict):
        return ["measurements: expected object"]
    errors: list[str] = []
    expected = {"schema_version", "source_ref", "source_digest", "producer", "artifact_sha256", "measured_at", "runner", "metrics"}
    if set(value) != expected:
        errors.append("measurements: unexpected or missing top-level fields")
    if value.get("schema_version") != "desktop-performance-measurements.v2":
        errors.append("measurements: unsupported schema version")
    if SOURCE_REF.fullmatch(source_ref) is None:
        errors.append("measurements: source_ref must be an immutable protected ref")
    if SOURCE_SHA.fullmatch(source_digest) is None:
        errors.append("measurements: source_digest must be a full commit SHA")
    recorded_ref = value.get("source_ref")
    if not isinstance(recorded_ref, str) or SOURCE_REF.fullmatch(recorded_ref) is None:
        errors.append("measurements: recorded source_ref must be an immutable protected ref")
    elif recorded_ref != source_ref:
        errors.append("measurements: source_ref does not match protected ref")
    recorded_digest = value.get("source_digest")
    if not isinstance(recorded_digest, str) or SOURCE_SHA.fullmatch(recorded_digest) is None:
        errors.append("measurements: recorded source_digest must be a full commit SHA")
    elif recorded_digest != source_digest:
        errors.append("measurements: source_digest does not match candidate")
    if value.get("producer") != "protected-runner":
        errors.append("measurements: producer must be protected-runner")
    try:
        datetime.fromisoformat(str(value.get("measured_at")).replace("Z", "+00:00"))
    except ValueError:
        errors.append("measurements: invalid measured_at")
    runner = value.get("runner")
    if not isinstance(runner, dict) or set(runner) != {"id", "image_sha256"} or not isinstance(runner.get("id"), str) or not runner["id"] or not isinstance(runner.get("image_sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", runner["image_sha256"]) is None:
        errors.append("measurements: invalid runner identity")
    metrics = value.get("metrics")
    if not isinstance(metrics, dict):
        return [*errors, "metrics: expected object"]
    for name, (unit, direction, limit) in METRICS.items():
        metric = metrics.get(name)
        if metric is None:
            errors.append(f"metrics: missing {name}")
            continue
        if not isinstance(metric, dict) or set(metric) != {"value", "unit"}:
            errors.append(f"{name}: malformed measurement")
            continue
        if metric["unit"] != unit:
            errors.append(f"{name}: unit must be {unit}")
        observed = metric["value"]
        if isinstance(observed, bool) or not isinstance(observed, (int, float)) or not math.isfinite(observed):
            errors.append(f"{name}: value must be a finite number")
        elif (direction == "maximum" and observed > limit) or (direction == "minimum" and observed < limit):
            relation = "exceeds maximum" if direction == "maximum" else "is below minimum"
            errors.append(f"{name}: {relation} {limit} {unit}")
    unknown = sorted(set(metrics) - set(METRICS))
    if unknown:
        errors.append(f"metrics: unknown {', '.join(unknown)}")
    if isinstance(metrics, dict) and value.get("artifact_sha256") != _metrics_digest(metrics):
        errors.append("measurements: artifact_sha256 does not match metrics")
    if not verify_external:
        errors.append("measurements: external attestation verification is required")
    else:
        expected_path = (root or Path(__file__).resolve().parents[2]) / CANONICAL_MEASUREMENTS
        if path.resolve() != expected_path.resolve() or path.is_symlink():
            errors.append("measurements: artifact path is not canonical")
        evidence_bundle = bundle or path.with_name(path.name + ".intoto.jsonl")
        if not evidence_bundle.is_file() or evidence_bundle.resolve() != evidence_bundle:
            errors.append("measurements: canonical attestation bundle is missing or invalid")
        protected = policy if policy is not None else protected_policy()
        if protected is None or protected.get("source_ref") != source_ref:
            errors.append("measurements: external verification policy is unavailable or mismatched")
        elif not errors and verify_attestation(path, evidence_bundle, protected, source_digest) is None:
            errors.append("measurements: attestation verification failed")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--verify-external", action="store_true")
    parser.add_argument("--source-ref", required=True, help="immutable protected qualification ref")
    parser.add_argument("--source-digest", required=True, help="exact 40-character candidate commit SHA")
    args = parser.parse_args(argv)
    errors = validate_measurements(args.measurements, source_ref=args.source_ref, source_digest=args.source_digest, verify_external=args.verify_external, bundle=args.bundle)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Desktop performance budgets passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
