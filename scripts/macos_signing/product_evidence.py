import json
import re

from .product_commands import canonical_product_templates
from .product_models import (
    ProductExecutionRecord,
    ProductSigningEvidence,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SCHEMA_VERSION = "macos-product-signing-evidence.v2"


def normalize_product_evidence(evidence: ProductSigningEvidence) -> bytes:
    if not _complete(evidence):
        raise ValueError("invalid product signing evidence")
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "kind": "macos-product-signing",
        "profile": "production-developer-id",
        "initial_candidate": _candidate(evidence.initial_candidate),
        "final_candidate": _candidate(evidence.final_candidate),
        "distribution": {
            "dmg_relative_name": evidence.dmg_relative_name,
            "dmg_sha256": evidence.dmg_sha256,
            "dmg_size": evidence.dmg_size,
        },
        "commands": [
            {
                "phase": record.template.phase,
                "program": record.template.program,
                "argv": list(record.template.argv),
                "outcome": record.outcome,
            }
            for record in evidence.commands
        ],
        "notarization": {"app": "accepted", "dmg": "accepted"},
        "stapling": {"app": "accepted", "dmg": "accepted"},
        "gatekeeper": "accepted",
        "stage": "COMPLETE",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if any(marker in encoded for marker in (b"SYNTHETIC-RAW-MARKER", b"password", b"private key")):
        raise ValueError("unsafe product signing evidence")
    return encoded + b"\n"


def _candidate(identity) -> dict[str, str]:
    return {
        "relative_name": identity.relative_name,
        "tree_sha256": identity.tree_sha256,
        "main_sha256": identity.main_sha256,
        "cli_sha256": identity.cli_sha256,
        "daemon_sha256": identity.daemon_sha256,
        "release_candidate_sha256": identity.release_candidate_sha256,
        "app_entitlements_sha256": identity.app_entitlements_sha256,
        "cli_entitlements_sha256": identity.cli_entitlements_sha256,
        "daemon_entitlements_sha256": identity.daemon_entitlements_sha256,
    }


def _complete(evidence: object) -> bool:
    if not isinstance(evidence, ProductSigningEvidence):
        return False
    candidates = (evidence.initial_candidate, evidence.final_candidate)
    digests = []
    for candidate in candidates:
        values = _candidate(candidate)
        if not values["relative_name"].endswith(".app"):
            return False
        digests.extend(value for key, value in values.items() if key != "relative_name")
    expected_templates = canonical_product_templates(
        evidence.initial_candidate.relative_name
    )
    return (
        all(isinstance(value, str) and _SHA256.fullmatch(value) for value in digests)
        and isinstance(evidence.dmg_relative_name, str)
        and evidence.dmg_relative_name.endswith(".dmg")
        and isinstance(evidence.dmg_sha256, str)
        and _SHA256.fullmatch(evidence.dmg_sha256) is not None
        and type(evidence.dmg_size) is int
        and evidence.dmg_size > 0
        and isinstance(evidence.commands, tuple)
        and len(evidence.commands) == len(expected_templates)
        and all(isinstance(record, ProductExecutionRecord) for record in evidence.commands)
        and all(record.outcome == "success" for record in evidence.commands)
        and tuple(record.template for record in evidence.commands)
        == expected_templates
    )
