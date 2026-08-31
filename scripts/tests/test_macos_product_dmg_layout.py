import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "darwin", "native hdiutil test")
class MacOSProductDmgLayoutTests(unittest.TestCase):
    def test_mounted_dmg_contains_intact_app_bundle_at_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "dmg-root"
            contents = source / "Runne.app" / "Contents"
            contents.mkdir(parents=True)
            (contents / "Info.plist").write_bytes(b"fixture\n")
            dmg = root / "Runne.dmg"
            mount = root / "mount"
            mount.mkdir()
            environment = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            }

            subprocess.run(
                (
                    "/usr/bin/hdiutil",
                    "create",
                    "-volname",
                    "Runne",
                    "-srcfolder",
                    str(source),
                    "-format",
                    "UDZO",
                    str(dmg),
                ),
                check=True,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            attached = False
            try:
                subprocess.run(
                    (
                        "/usr/bin/hdiutil",
                        "attach",
                        "-readonly",
                        "-nobrowse",
                        "-mountpoint",
                        str(mount),
                        str(dmg),
                    ),
                    check=True,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                attached = True
                self.assertTrue((mount / "Runne.app" / "Contents").is_dir())
                self.assertFalse((mount / "Contents").exists())
            finally:
                if attached:
                    subprocess.run(
                        ("/usr/bin/hdiutil", "detach", str(mount)),
                        check=False,
                        env=environment,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                shutil.rmtree(mount, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
