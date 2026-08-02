from pathlib import Path


parts = Path(__file__).with_name("validate_architecture_parts")
for name in ('part_01.inc', 'part_02.inc'):
    exec((parts / name).read_text(encoding="utf-8"))
