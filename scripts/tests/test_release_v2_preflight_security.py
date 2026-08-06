import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.release_v2 import preflight
from scripts.release_v2 import repository_snapshot
from scripts.release_v2.model import FailureCodeV1 as FailureCode, ReleaseFailure
from scripts.release_v2.preflight import BuildRequest, build_input_identity, preflight_candidate


class PreflightSecurityTests(unittest.TestCase):
    def repositories(self) -> tuple[Path, Path, BuildRequest]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "source"
        source.mkdir()
        for name, value in (("Cargo.lock", "cargo\n"), ("pnpm-lock.yaml", "pnpm\n"), ("main.txt", "source\n")):
            (source / name).write_text(value, encoding="utf-8")
        self.git(source, "init")
        self.git(source, "add", ".")
        self.git(source, "commit", "-m", "fixture")
        candidate = Path(temporary.name) / "candidate"
        shutil.copytree(source, candidate)
        request = BuildRequest("1.0.0", "x86_64-unknown-linux-gnu", "linux", ("a" * 64,), "rust-1.97.1", "release", 0)
        return source, candidate, request

    @staticmethod
    def git(root: Path, *arguments: str) -> None:
        subprocess.run(["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assert_failure(self, callback, code: FailureCode) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)

    def assert_success(self, callback) -> None:
        try:
            callback()
        except ReleaseFailure as error:
            self.fail(f"unexpected {error.code.value}")

    def test_commands_are_limited_to_raw_object_and_index_reads(self) -> None:
        source, candidate, request = self.repositories()
        commands: list[tuple[str, ...]] = []
        run = subprocess.run

        def capture(command, *args, **kwargs):
            if command[0] == "git":
                commands.append(tuple(command[1:]))
            return run(command, *args, **kwargs)

        with patch("subprocess.run", side_effect=capture):
            preflight_candidate(source, candidate, build_input_identity(source, request))
        self.assertTrue(commands)
        for command in commands:
            self.assertEqual(command[:2], ("--no-pager", "--no-replace-objects"))
            self.assertRegex(command[2], r"--git-dir=/proc/self/fd/[0-9]+")
            raw = command[3:]
            self.assertTrue(raw == ("cat-file", "--batch") or (len(raw) == 5 and raw[:4] == ("ls-tree", "-r", "-z", "--full-tree") and len(raw[4]) == 40))
        rejected = (("fetch",), ("status",), ("submodule", "status"), ("diff",), ("show",), ("ls-tree", "-r", "-z", "--full-tree", "0" * 40, "--work-tree=/tmp"), ("cat-file", "--batch", "fetch"))
        with patch.object(repository_snapshot.subprocess, "run") as run:
            for arguments in rejected:
                with self.subTest(arguments=arguments):
                    self.assert_failure(lambda arguments=arguments: repository_snapshot._git(-1, arguments), FailureCode.CANDIDATE_DIRTY)
            run.assert_not_called()

    def test_repository_helpers_are_not_executed(self) -> None:
        source, candidate, request = self.repositories()
        marker, helper = source.parent / "marker", source.parent / "helper"
        helper.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        helper.chmod(0o755)
        self.git(source, "config", "core.fsmonitor", str(helper))
        self.git(source, "config", "filter.hostile.clean", str(helper))
        self.assert_success(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)))
        self.assertFalse(marker.exists())

    def test_staged_unstaged_untracked_and_ignored_entries_are_dirty(self) -> None:
        for kind in ("staged", "unstaged", "untracked", "ignored"):
            with self.subTest(kind=kind):
                source, candidate, request = self.repositories()
                if kind == "staged":
                    (candidate / "main.txt").write_text("changed\n", encoding="utf-8")
                    self.git(candidate, "add", "main.txt")
                elif kind == "unstaged":
                    (candidate / "main.txt").write_text("changed\n", encoding="utf-8")
                else:
                    if kind == "ignored":
                        (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
                        self.git(source, "add", ".gitignore")
                        self.git(source, "commit", "-m", "ignore")
                        shutil.rmtree(candidate)
                        shutil.copytree(source, candidate)
                    (candidate / ("ignored.txt" if kind == "ignored" else "extra.txt")).write_text("changed\n", encoding="utf-8")
                self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)

    def test_second_capture_error_is_input_mutation(self) -> None:
        source, candidate, request = self.repositories()
        build = build_input_identity(source, request)
        snapshot = preflight._snapshot(source, FailureCode.SOURCE_REVISION_INVALID)
        with patch.object(preflight, "_capture_repository", side_effect=(snapshot, snapshot, snapshot, OSError("changed")), create=True):
            self.assert_failure(lambda: preflight_candidate(source, candidate, build), FailureCode.INPUT_MUTATION_DETECTED)

    def test_second_capture_head_or_index_mutation_is_input_mutation(self) -> None:
        for name, value in (("HEAD", b"0" * 40 + b"\n"), ("index", b"invalid")):
            with self.subTest(name=name):
                source, candidate, request = self.repositories()
                build, original, calls = build_input_identity(source, request), preflight._capture_repository, 0

                def capture(root: Path) -> tuple[str, str, str, str]:
                    nonlocal calls
                    if root == candidate:
                        calls += 1
                        if calls == 2:
                            (candidate / ".git" / name).write_bytes(value)
                    return original(root)

                with patch.object(preflight, "_capture_repository", side_effect=capture):
                    self.assert_failure(lambda: preflight_candidate(source, candidate, build), FailureCode.INPUT_MUTATION_DETECTED)
        source, candidate, request = self.repositories()
        build, read = build_input_identity(source, request), repository_snapshot._read_fd

        def mutate(fd: int) -> bytes:
            value = read(fd)
            (source / "main.txt").write_text("source\n", encoding="utf-8")
            return value

        with self.subTest(name="first_capture_worktree_fstat"):
            with patch.object(repository_snapshot, "_read_fd", side_effect=mutate):
                self.assert_failure(lambda: preflight_candidate(source, candidate, build), FailureCode.INPUT_MUTATION_DETECTED)

    def test_file_and_parent_symlinks_do_not_follow_external_sentinel(self) -> None:
        source, candidate, request = self.repositories()
        sentinel = source.parent / "external"
        sentinel.write_text("external sentinel\n", encoding="utf-8")
        (candidate / "main.txt").unlink()
        (candidate / "main.txt").symlink_to(sentinel)
        self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)
        (candidate / "main.txt").unlink()
        (candidate / "directory").symlink_to(source.parent)
        self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "external sentinel\n")

    def gitlink_repositories(self, path: str = "module", nested: bool = False) -> tuple[Path, Path, BuildRequest]:
        source, candidate, request = self.repositories()
        child = source.parent / "child"
        child.mkdir()
        (child / "child.txt").write_text("child\n", encoding="utf-8")
        self.git(child, "init")
        self.git(child, "add", ".")
        self.git(child, "commit", "-m", "child")
        if nested:
            grandchild = source.parent / "grandchild"
            grandchild.mkdir()
            (grandchild / "grandchild.txt").write_text("grandchild\n", encoding="utf-8")
            self.git(grandchild, "init")
            self.git(grandchild, "add", ".")
            self.git(grandchild, "commit", "-m", "grandchild")
            self.git(child, "-c", "protocol.file.allow=always", "submodule", "add", str(grandchild), "nested")
            self.git(child, "commit", "-m", "nested")
        self.git(source, "-c", "protocol.file.allow=always", "submodule", "add", str(child), path)
        self.git(source, "commit", "-m", "module")
        shutil.rmtree(candidate)
        shutil.copytree(source, candidate)
        return source, candidate, request

    def test_clean_nested_tree_is_accepted(self) -> None:
        source, candidate, request = self.repositories()
        (source / "nested" / "deep").mkdir(parents=True)
        (source / "nested" / "deep" / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        self.git(source, "add", ".")
        self.git(source, "commit", "-m", "nested")
        shutil.rmtree(candidate)
        shutil.copytree(source, candidate)
        self.assert_success(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_nested_untracked_and_ignored_files_are_dirty(self) -> None:
        for name in ("extra.txt", "ignored.txt"):
            with self.subTest(name=name):
                source, candidate, request = self.repositories()
                (source / "nested" / "deep").mkdir(parents=True)
                (source / "nested" / "deep" / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
                (source / "nested" / "deep" / "tracked.txt").write_text("tracked\n", encoding="utf-8")
                self.git(source, "add", ".")
                self.git(source, "commit", "-m", "nested")
                shutil.rmtree(candidate)
                shutil.copytree(source, candidate)
                (candidate / "nested" / "deep" / name).write_text("extra\n", encoding="utf-8")
                self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)

    def test_clean_pinned_submodule_is_accepted(self) -> None:
        source, candidate, request = self.gitlink_repositories()
        self.assert_success(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_dirty_or_mismatched_submodule_is_dirty(self) -> None:
        for changed, commit in (("dirty\n", False), ("mismatched\n", True)):
            with self.subTest(commit=commit):
                source, candidate, request = self.gitlink_repositories()
                module = candidate / "module"
                (module / "child.txt").write_text(changed, encoding="utf-8")
                if commit:
                    self.git(module, "add", "child.txt")
                    self.git(module, "commit", "-m", "mismatch")
                self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)

    def test_nested_submodule_path_is_checked(self) -> None:
        for dirty in (False, True):
            with self.subTest(dirty=dirty):
                source, candidate, request = self.gitlink_repositories("nested/module")
                if dirty:
                    (candidate / "nested" / "module" / "child.txt").write_text("dirty\n", encoding="utf-8")
                    self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)
                else:
                    self.assert_success(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)))

    def test_uninitialized_or_unsafe_submodule_is_dirty(self) -> None:
        for unsafe in (False, True):
            with self.subTest(unsafe=unsafe):
                source, candidate, request = self.gitlink_repositories()
                if unsafe:
                    (candidate / "module" / ".git").write_text("gitdir: /unsafe/external\n", encoding="utf-8")
                else:
                    shutil.rmtree(candidate / "module")
                self.assert_failure(lambda: preflight_candidate(source, candidate, build_input_identity(source, request)), FailureCode.CANDIDATE_DIRTY)

    def test_nested_submodule_shape_is_dirty(self) -> None:
        source, _, request = self.gitlink_repositories(nested=True)
        self.assert_failure(lambda: build_input_identity(source, request), FailureCode.CANDIDATE_DIRTY)

    def test_fifo_snapshot_is_rejected_promptly_without_descriptor_leak(self) -> None:
        script = """import os
import sys
from pathlib import Path
from scripts.release_v2.model import ReleaseFailure
from scripts.release_v2.preflight import BuildRequest, build_input_identity, preflight_candidate
source, candidate = map(Path, sys.argv[1:])
request = BuildRequest("1.0.0", "x86_64-unknown-linux-gnu", "linux", ("a" * 64,), "rust-1.97.1", "release", 0)
before = len(os.listdir("/proc/self/fd"))
try:
    preflight_candidate(source, candidate, build_input_identity(source, request))
except ReleaseFailure as error:
    print(error.code.value, before == len(os.listdir("/proc/self/fd")))
"""
        for gitlink in (False, True):
            with self.subTest(gitlink=gitlink):
                source, candidate, request = self.gitlink_repositories() if gitlink else self.repositories()
                target = candidate / "module" / ".git" if gitlink else candidate / "main.txt"
                target.unlink()
                os.mkfifo(target)
                try:
                    result = subprocess.run([sys.executable, "-c", script, str(source), str(candidate)], cwd=Path(__file__).parents[2], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                except subprocess.TimeoutExpired:
                    self.fail("FIFO snapshot did not finish promptly")
                self.assertEqual(result.stdout, "CandidateDirty True\n")

    def test_preflight_preserves_index_bytes_and_metadata(self) -> None:
        source, candidate, request = self.repositories()

        def index(root: Path) -> tuple[str, int, int, int, int]:
            value = root / ".git" / "index"
            item = value.stat()
            return hashlib.sha256(value.read_bytes()).hexdigest(), stat.S_IMODE(item.st_mode), item.st_size, item.st_mtime_ns, item.st_ctime_ns

        before = index(source), index(candidate)
        preflight_candidate(source, candidate, build_input_identity(source, request))
        self.assertEqual((index(source), index(candidate)), before)


if __name__ == "__main__":
    unittest.main()
