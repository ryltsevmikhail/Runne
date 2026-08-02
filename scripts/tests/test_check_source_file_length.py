import importlib.util
import pathlib
import sys
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "check-source-file-length.py"
SPEC = importlib.util.spec_from_file_location("check_source_file_length", SCRIPT_PATH)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


class CheckSourceFileLengthTests(unittest.TestCase):
    def test_exact_limit_passes_and_next_line_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "exact.rs").write_text("x\n" * 300, encoding="utf-8")
            (root / "over.rs").write_text("x\n" * 301, encoding="utf-8")

            checked, violations = checker.audit_paths(
                root,
                ["exact.rs", "over.rs"],
                max_lines=300,
                excludes=(),
            )

        self.assertEqual([item.path for item in checked], ["exact.rs", "over.rs"])
        self.assertEqual([(item.path, item.lines) for item in violations], [("over.rs", 301)])

    def test_binary_files_are_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "icon.rs").write_bytes(b"header\0binary\n" * 500)

            checked, violations = checker.audit_paths(
                root,
                ["icon.rs"],
                max_lines=1,
                excludes=(),
            )

        self.assertEqual(checked, [])
        self.assertEqual(violations, [])

    def test_unterminated_final_line_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            path = root / "unterminated.rs"
            path.write_bytes((b"x\n" * 300) + b"x")

            checked, violations = checker.audit_paths(
                root,
                ["unterminated.rs"],
                max_lines=300,
                excludes=(),
            )

        self.assertEqual([(item.path, item.lines) for item in checked], [("unterminated.rs", 301)])
        self.assertEqual([(item.path, item.lines) for item in violations], [("unterminated.rs", 301)])

    def test_included_source_without_a_standard_suffix_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            included = root / "implementation.inc"
            included.write_text("x\n" * 301, encoding="utf-8")

            checked, violations = checker.audit_paths(
                root,
                ["implementation.inc"],
                max_lines=300,
                excludes=(),
            )

        self.assertEqual([(item.path, item.lines) for item in checked], [("implementation.inc", 301)])
        self.assertEqual([(item.path, item.lines) for item in violations], [("implementation.inc", 301)])

    def test_missing_paths_are_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)

            checked, violations = checker.audit_paths(
                root,
                ["deleted.ts"],
                max_lines=300,
                excludes=(),
            )

        self.assertEqual(checked, [])
        self.assertEqual(violations, [])

    def test_excluded_prefix_and_glob_are_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "upstream").mkdir()
            (root / "generated").mkdir()
            (root / "upstream" / "copy.rs").write_text("x\n" * 400, encoding="utf-8")
            (root / "generated" / "bundle.rs").write_text("x\n" * 400, encoding="utf-8")

            checked, violations = checker.audit_paths(
                root,
                ["upstream/copy.rs", "generated/bundle.rs"],
                max_lines=300,
                excludes=("upstream/", "generated/*.rs"),
            )

        self.assertEqual(checked, [])
        self.assertEqual(violations, [])

    def test_violations_are_sorted_by_size_then_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            (root / "z.rs").write_text("x\n" * 301, encoding="utf-8")
            (root / "a.rs").write_text("x\n" * 350, encoding="utf-8")
            (root / "b.rs").write_text("x\n" * 350, encoding="utf-8")

            _, violations = checker.audit_paths(
                root,
                ["z.rs", "b.rs", "a.rs"],
                max_lines=300,
                excludes=(),
            )

        self.assertEqual(
            [(item.path, item.lines) for item in violations],
            [("a.rs", 350), ("b.rs", 350), ("z.rs", 301)],
        )


if __name__ == "__main__":
    unittest.main()
