"""Load documentation validation phases in one shared execution context."""
from pathlib import Path


parts = Path(__file__).with_name("validate_docs_parts")
for name in ("schema_and_profile.inc", "documentation_rules.inc"):
    exec((parts / name).read_text(encoding="utf-8"))
