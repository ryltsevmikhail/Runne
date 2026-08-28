from pathlib import Path


parts = Path(__file__).with_name("validate_architecture_parts")
for name in ('part_01.inc', 'part_02.inc', 'part_03.inc', 'part_04.inc'):
    exec((parts / name).read_text(encoding="utf-8"))
