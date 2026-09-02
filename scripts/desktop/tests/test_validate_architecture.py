from pathlib import Path


parts = Path(__file__).with_name("validate_architecture_parts")
for name in (
    'part_01.inc', 'part_02.inc', 'part_03.inc', 'part_04.inc',
    'part_05.inc', 'part_06.inc', 'part_07.inc',
):
    exec((parts / name).read_text(encoding="utf-8"))
