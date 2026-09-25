"""Checks immutable published V2 identity and active raw-secret ingress."""

from __future__ import annotations

import hashlib
import json
import re


def validate_published_credential_contracts(validator: object) -> None:
    pins = {
        "contracts/gocode-ui-client-2/schemas/provider-credentials-v1.schema.json": "ff0a9e3840d286943a3a0f396258d9e27b4c01c774cf94f739983480092df09b",
        "contracts/gocode-ui-client-2/openapi.json": "4a270adaa6e362f62ec3a0a7769720440e2ba8db63006f23d8578a17a974fab2",
    }
    bundle_path = "contracts/gocode-ui-client-2/bundle.json"
    try:
        bundle = json.loads(validator.read(bundle_path))
        if bundle.get("apiProfileId") != "gocode-ui-client/2":
            validator.fail("SURFACE_PUBLIC_CONTRACT_V1", bundle_path, "published V2 profile identity changed")
        digests = bundle["artifactDigests"]
        if not isinstance(digests, list) or any(
            not isinstance(entry, dict) for entry in digests
        ):
            raise TypeError("artifactDigests must be an array of objects")
        members = {entry.get("path"): entry.get("sha256") for entry in digests}
        for path, expected in pins.items():
            actual = hashlib.sha256((validator.root / path).read_bytes()).hexdigest()
            relative = path.removeprefix("contracts/gocode-ui-client-2/")
            if actual != expected or members.get(relative) != expected:
                validator.fail("SURFACE_PUBLIC_CONTRACT_V1", path, "frozen published V2 artifact bytes or bundle digest changed")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        validator.fail("SURFACE_PUBLIC_CONTRACT_V1", bundle_path, f"invalid guarded V2 artifact identity: {error}")

    api_path = "crates/runne-api/src/provider_credential_enrollment/types.rs"
    api = validator.read(api_path)
    for marker, fields in (
        ("struct BeginWire", {"action", "provider", "expected_lifecycle_revision", "command_identity", "idempotency_key", "native_intent_id"}),
        ("struct VerifyWire", {"provider", "expected_lifecycle_revision", "verification_kind", "command_identity", "native_intent_id"}),
    ):
        validator.exact_fields(api_path, marker, fields, "SURFACE_ACTIVE_V2_INGRESS")
        declaration = api.find(marker)
        prefix = api[:declaration] if declaration >= 0 else ""
        attributes = re.search(r"(?:(?:\s*#\[[^\]]+\]\s*)+)$", prefix)
        if attributes is None or not re.search(
            r"\bdeny_unknown_fields\b", attributes.group(0)
        ):
            validator.fail(
                "SURFACE_ACTIVE_V2_INGRESS",
                api_path,
                f"{marker} must reject unknown fields on its own wire declaration",
            )
