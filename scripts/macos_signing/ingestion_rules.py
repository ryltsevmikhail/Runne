"""Нормативное зеркало JSON Schema `docs/schemas/macos-production-evidence-v1.schema.json`.

Модуль содержит канонические константы и чистые функции, которые
реализуют правила ингестии production evidence для macOS signing.
Значения констант являются единственным источником истины для
`ingestion.py`, `claim_activation.py` и `finalize.py`; расхождение
между этим модулем и схемой ловится drift-тестами.

Инварианты чистоты: модуль не читает переменные окружения, не запускает
внешние процессы, не выполняет сетевых операций и не записывает файлы.
Входные значения не включаются ни в исключения, ни в результаты (кроме
возвращаемых канонических байтов и дайджестов) — redaction-контракт.
"""

import hashlib
import json
import re

SCHEMA_VERSION = "macos-production-evidence.v1"
KIND = "macos-production-signing"
PROFILE = "production-developer-id"
PLATFORM = "darwin"
ENVIRONMENT_CLASS = "PRODUCTION"
AUTHENTICITY_METHOD = "HUMAN_OPERATOR"
PRODUCER_LANE = "macos-human-operator"

FRESHNESS_WINDOW_SECONDS = 604800

CANONICAL_PHASES = (
    "sign-daemon",
    "verify-daemon",
    "metadata-daemon",
    "requirement-daemon",
    "entitlements-daemon",
    "sign-app",
    "verify-app",
    "metadata-app",
    "requirement-app",
    "entitlements-app",
    "notary-submit",
    "staple-staple",
    "staple-validate",
    "gatekeeper",
)

PHASE_OPERATIONS = {
    "sign-daemon": "sign",
    "verify-daemon": "verify",
    "metadata-daemon": "metadata",
    "requirement-daemon": "requirement",
    "entitlements-daemon": "entitlements",
    "sign-app": "sign",
    "verify-app": "verify",
    "metadata-app": "metadata",
    "requirement-app": "requirement",
    "entitlements-app": "entitlements",
    "notary-submit": "submit",
    "staple-staple": "staple",
    "staple-validate": "validate",
    "gatekeeper": "assess",
}

SIGN_PHASES = ("sign-daemon", "sign-app")

AD_HOC_PROFILE = "development-ad-hoc"
SYNTHETIC_ENVIRONMENT_CLASSES = ("FIXTURE", "SYNTHETIC")
SYNTHETIC_SCHEMA_VERSION = "evidence-v1"
SYNTHETIC_KIND = "development-signing"

SECRET_SUBSTRINGS = (
    "-----begin",
    "private key",
    "begin certificate",
    "begin openssh",
    "begin pgp",
    "begin encrypted",
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "bearer ",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def sha256_ok(value) -> bool:
    """Return whether `value` is a 64-character lowercase hex digest string."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def contains_secret_marker(value: str) -> bool:
    """Return whether a text value looks like a credential or private path."""
    lowered = value.lower()
    if any(marker in lowered for marker in SECRET_SUBSTRINGS):
        return True
    return value.startswith("/") or value.startswith("~") or "Users/" in value or "$" in value


def scan_secrets(payload) -> bool:
    """Recursively scan keys and values of a JSON-like payload for secret markers."""
    if isinstance(payload, dict):
        for key, item in payload.items():
            if contains_secret_marker(str(key)):
                return True
            if scan_secrets(item):
                return True
        return False
    if isinstance(payload, list):
        return any(scan_secrets(item) for item in payload)
    if isinstance(payload, str):
        return contains_secret_marker(payload)
    return False


def freshness_ok(produced_at, fresh_until, now) -> bool:
    """Return whether the evidence time window is fresh relative to `now`."""
    if type(produced_at) is not int or type(fresh_until) is not int or type(now) is not int:
        return False
    if produced_at < 0 or produced_at >= fresh_until:
        return False
    if fresh_until - produced_at > FRESHNESS_WINDOW_SECONDS:
        return False
    return produced_at <= now <= fresh_until


def canonical_evidence_bytes(payload: dict) -> bytes:
    """Serialize a payload without the top-level `evidence_sha256` key."""
    document = {key: value for key, value in payload.items() if key != "evidence_sha256"}
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def evidence_digest(payload: dict) -> str:
    """Return the canonical sha256 digest of a payload."""
    return hashlib.sha256(canonical_evidence_bytes(payload)).hexdigest()


def _reject_constant(value: str) -> None:
    raise ValueError(f"rejected non-finite constant: {value}")


def _unique_key_pairs(pairs: list) -> dict:
    document: dict = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate key: {key}")
        document[key] = value
    return document


def strict_json_loads(text) -> tuple[object, bool]:
    """Parse JSON text rejecting NaN/Infinity and duplicate keys."""
    try:
        return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_key_pairs), True
    except (ValueError, TypeError):
        return None, False
