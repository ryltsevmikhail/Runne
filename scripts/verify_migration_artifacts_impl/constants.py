"""Shared paths, validation constants, and mutable diagnostic state."""

import os
import re

BASE = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SCHEMA_PATH = os.path.join(BASE, "docs", "schemas", "migration-evidence-v1.schema.json")
GOLDEN_DIR = os.path.join(BASE, "docs", "golden", "migration")
BASELINE_SHA = "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

BLACKLIST_KEYS = {
    "secret",
    "token",
    "prompt",
    "authorization",
    "cookie",
    "user_id",
    "taskrun_id",
    "path_raw",
}

errors: list[str] = []
warnings: list[str] = []
