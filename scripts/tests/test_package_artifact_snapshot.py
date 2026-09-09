"""Descriptor-pinning regressions for staged Desktop package artifacts."""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.desktop import package_artifact_snapshot
from scripts.desktop import native_package_probe
from scripts.desktop import windows_package_cleanup
from scripts.desktop import windows_package_snapshot


class PackageArtifactSnapshotTests(unittest.TestCase):
    def test_windows_native_probe_accepts_live_registered_snapshot_only(self) -> None:
        completed = __import__("subprocess").CompletedProcess([], 0, "", "")
        snapshot = object()

        class Lease:
            def is_active_for(self, candidate: object) -> bool:
                return candidate is snapshot

        with patch.object(native_package_probe.os, "name", "nt"), patch.object(
            native_package_probe, "is_pinned_snapshot_path", return_value=True
        ), patch.object(native_package_probe.subprocess, "run", return_value=completed) as native_call:
            result = native_package_probe.native_probe("windows-10-22h2-x86_64", "install", r"C:\\pinned\\artifact.exe", snapshot, Lease())
        self.assertEqual(result["status"], "verified")
        self.assertNotIn("pass_fds", native_call.call_args.kwargs)

    def test_windows_native_probe_rejects_arbitrary_path(self) -> None:
        snapshot = object()

        class Lease:
            def is_active_for(self, candidate: object) -> bool:
                return candidate is snapshot

        with patch.object(native_package_probe.os, "name", "nt"), patch.object(
            native_package_probe, "is_pinned_snapshot_path", return_value=False
        ), patch.object(native_package_probe.subprocess, "run") as native_call:
            result = native_package_probe.native_probe("windows-10-22h2-x86_64", "install", r"C:\\arbitrary\\artifact.exe", snapshot, Lease())
        self.assertEqual(result, {"status": "blocked", "detail": "PACKAGE_ARTIFACT_PATH_UNSAFE"})
        native_call.assert_not_called()

    def test_windows_child_exit_code_is_reported_as_blocked(self) -> None:
        snapshot = object()

        class Lease:
            def is_active_for(self, candidate: object) -> bool:
                return candidate is snapshot

        completed = __import__("subprocess").CompletedProcess([], 17, "", "child failed")
        with patch.object(native_package_probe.os, "name", "nt"), patch.object(
            native_package_probe, "is_pinned_snapshot_path", return_value=True
        ), patch.object(native_package_probe.subprocess, "run", return_value=completed) as native_call:
            result = native_package_probe.native_probe("windows-10-22h2-x86_64", "install", r"C:\\pinned\\artifact.exe", snapshot, Lease())
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["returncode"], 17)
        command = native_call.call_args.args[0][-1]
        self.assertIn("-PassThru", command)
        self.assertIn("$process.ExitCode", command)
        uninstall = native_package_probe._command("windows-10-22h2-x86_64", "uninstall", r"C:\\pinned\\artifact.exe")[-1]
        self.assertIn("-PassThru", uninstall)
        self.assertIn("$process.ExitCode", uninstall)

    def test_snapshot_close_waits_for_active_use_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Runne.deb").write_bytes(b"admitted")
            snapshot = package_artifact_snapshot.stage_artifact(root, "Runne.deb", "deb")
            lease = snapshot.acquire_use()
            started, finished = threading.Event(), threading.Event()

            def close_snapshot() -> None:
                started.set()
                snapshot.close()
                finished.set()

            worker = threading.Thread(target=close_snapshot)
            worker.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(finished.wait(0.05))
            self.assertFalse(snapshot._closed)
            lease.release()
            self.assertTrue(finished.wait(1))
            worker.join()
            self.assertTrue(snapshot._closed)
    def test_windows_identity_includes_index_low(self) -> None:
        self.assertTrue(windows_package_snapshot._same_identity((7, 11, 13), (7, 11, 13)))
        self.assertFalse(windows_package_snapshot._same_identity((7, 11, 13), (7, 11, 14)))

    def test_windows_copy_failure_removes_staged_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Runne.deb"
            source.write_bytes(b"source")
            staged = root / "staged"
            staged.mkdir()
            identity = (7, 11, 13)

            def open_path(path: Path, _directory: bool, _delete: bool = False) -> tuple[int, tuple[int, int, int]]:
                return (1, identity) if path == root else (2, identity)

            with (
                patch.object(windows_package_snapshot.tempfile, "mkdtemp", return_value=str(staged)),
                patch.object(windows_package_snapshot, "_open_path", side_effect=open_path),
                patch.object(windows_package_snapshot, "_open_child_relative", return_value=(3, identity)),
                patch.object(windows_package_snapshot, "_identity", return_value=identity),
                patch.object(windows_package_snapshot, "_close"),
                patch.object(windows_package_snapshot, "clear_stage", side_effect=lambda *_args: staged.rmdir()),
                patch.object(windows_package_snapshot, "_read_write", side_effect=windows_package_snapshot.WindowsSnapshotError("COPY_FAILED")),
            ):
                with self.assertRaises(windows_package_snapshot.WindowsSnapshotError):
                    windows_package_snapshot.stage_artifact(root, "Runne.deb", "deb")

            self.assertFalse(staged.exists())

    def test_windows_cleanup_clears_pinned_tree_without_following_replacement_path(self) -> None:
        opened: list[tuple[int, bool]] = []
        deleted: list[int] = []
        children = {10: [("original-dir", True), ("original-file", False)], 11: []}

        def enumerate_children(handle: int) -> list[tuple[str, bool]]:
            return children[handle]

        def open_child(parent: int, name: str, directory: bool, delete: bool) -> tuple[int, tuple[int, int, int]]:
            opened.append((parent, delete))
            return (11 if directory else 12), (7, 11, 13)

        with patch.object(windows_package_cleanup, "_delete_handle", side_effect=deleted.append):
            windows_package_cleanup.clear_stage(10, enumerate_children, open_child, lambda _handle: None)

        self.assertEqual(opened, [(10, True), (10, True)])
        self.assertEqual(deleted, [11, 12, 10])

    def test_windows_snapshot_close_clears_moved_root_not_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            original, moved = base / "stage", base / "stage-moved"
            original.mkdir()
            (original / "artifact").write_bytes(b"admitted")
            original.rename(moved)
            original.mkdir()
            (original / "artifact").write_bytes(b"replacement")
            snapshot = windows_package_snapshot.WindowsSnapshot(
                original / "artifact", original, (7, 11, 13), 10, [10], 20, (7, 14, 15), "nsis"
            )
            windows_package_cleanup.register(snapshot.path, snapshot, (7, 14, 15))

            def clear_pinned_root(handle: int, *_args: object) -> None:
                self.assertEqual(handle, 10)
                shutil.rmtree(moved)

            with patch.object(windows_package_snapshot, "clear_stage", side_effect=clear_pinned_root), patch.object(
                windows_package_snapshot, "_close"
            ), patch.object(windows_package_cleanup.os, "name", "nt"):
                self.assertTrue(windows_package_cleanup.is_pinned_snapshot_path(snapshot.path))
                snapshot.close()
                self.assertFalse(windows_package_cleanup.is_pinned_snapshot_path(snapshot.path))
            self.assertEqual((original / "artifact").read_bytes(), b"replacement")
            self.assertFalse(moved.exists())

    def test_windows_platform_uses_handle_snapshot_boundary(self) -> None:
        fake_snapshot = object()
        root = Path("C:/checkout")
        with patch.object(package_artifact_snapshot.os, "name", "nt"), patch.object(
            package_artifact_snapshot, "_windows_stage_artifact", return_value=fake_snapshot, create=True
        ) as stage:
            result = package_artifact_snapshot.stage_artifact(root, "Runne.deb", "deb")
        self.assertIs(result, fake_snapshot)
        stage.assert_called_once_with(root, "Runne.deb", "deb")

    def test_artifact_fd_closes_when_post_open_validation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Runne.deb").write_bytes(b"admitted")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            real_close = os.close
            closed: list[int] = []

            def fail_fstat(_fd: int) -> os.stat_result:
                raise OSError("injected fstat failure")

            def track_close(fd: int) -> None:
                closed.append(fd)
                real_close(fd)

            try:
                with patch.object(package_artifact_snapshot.os, "fstat", side_effect=fail_fstat), patch.object(
                    package_artifact_snapshot.os, "close", side_effect=track_close
                ):
                    with self.assertRaises(package_artifact_snapshot.ArtifactAdmissionError):
                        package_artifact_snapshot._open_artifact(root_fd, ("Runne.deb",), "deb")
            finally:
                real_close(root_fd)
            self.assertGreaterEqual(len(closed), 2)

    def test_root_swap_before_initial_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Runne.deb").write_bytes(b"admitted")
            fd_count_before = len(os.listdir("/dev/fd"))
            parent_fd: int | None = None
            names: list[str] = []
            real_open = lambda parent, name: os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)

            def swap_before_open(parent: int, name: str) -> int:
                nonlocal parent_fd
                parent_fd = os.dup(parent)
                moved = f"{name}-moved"
                names.extend((name, moved))
                os.rename(name, moved, src_dir_fd=parent, dst_dir_fd=parent)
                os.mkdir(name, 0o700, dir_fd=parent)
                return real_open(parent, name)

            try:
                with patch.object(package_artifact_snapshot, "_open_stage_fd", side_effect=swap_before_open):
                    with self.assertRaises(package_artifact_snapshot.ArtifactAdmissionError) as failure:
                        package_artifact_snapshot.stage_artifact(root, "Runne.deb", "deb")
                self.assertEqual(failure.exception.code, "PACKAGE_ARTIFACT_PATH_UNSAFE")
            finally:
                if parent_fd is not None:
                    for name in names:
                        try:
                            os.rmdir(name, dir_fd=parent_fd)
                        except OSError:
                            pass
                    os.close(parent_fd)
            self.assertEqual(len(os.listdir("/dev/fd")), fd_count_before)

    def test_copy_uses_pinned_root_when_staging_path_is_swapped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Runne.deb").write_bytes(b"admitted")
            real_temporary_directory = package_artifact_snapshot.tempfile.TemporaryDirectory
            real_copy_file = package_artifact_snapshot._copy_file
            staging_roots: list[Path] = []
            moved_root: Path | None = None

            def create_stage(*args: object, **kwargs: object) -> tempfile.TemporaryDirectory[str]:
                stage = real_temporary_directory(*args, **kwargs)
                staging_roots.append(Path(stage.name))
                return stage

            def swap_before_copy(*args: object) -> None:
                nonlocal moved_root
                stage = staging_roots[0]
                moved_root = stage.with_name(f"{stage.name}-moved")
                stage.rename(moved_root)
                stage.mkdir()
                (stage / "artifact").write_bytes(b"replacement")
                real_copy_file(*args)

            snapshot = None
            try:
                with patch.object(package_artifact_snapshot.tempfile, "TemporaryDirectory", side_effect=create_stage), patch.object(package_artifact_snapshot, "_copy_file", side_effect=swap_before_copy):
                    snapshot = package_artifact_snapshot.stage_artifact(root, "Runne.deb", "deb")
                self.assertEqual(snapshot.path.read_bytes(), b"admitted")
                self.assertEqual(hashlib.sha256(snapshot.path.read_bytes()).hexdigest(), hashlib.sha256(b"admitted").hexdigest())
            finally:
                if snapshot is not None:
                    snapshot.close()
                for path in (staging_roots + ([moved_root] if moved_root else [])):
                    if path.exists():
                        path.chmod(0o700)
                        shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
