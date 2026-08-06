"""Load architecture validation phases in one shared execution context."""
from pathlib import Path


parts = Path(__file__).with_name("validate_architecture_impl_parts")
for name in ("checks.inc", "entrypoint.inc"):
    exec((parts / name).read_text(encoding="utf-8"))
