class PendingPackagedWriterDependencyTest(unittest.TestCase):
    def test_low_level_crate_has_the_exact_target_macos_dependency_set(self):
        self.assertEqual(
            [],
            architecture.find_macos_process_identity_crate_dependency_violations(
                self.packages()
            ),
        )

    def test_rejects_every_dependency_shape_mutation(self):
        mutations = (
            ("missing", "security-framework", "delete", None),
            ("extra", "security-framework", "name", "runne-platform-desktop"),
            ("wrong target", "core-foundation", "target", None),
            ("dev only", "security-framework-sys", "kind", "dev"),
            ("floating core foundation", "core-foundation", "req", "^0.10"),
            ("floating nix", "nix", "req", "^0.31"),
            ("nix defaults", "nix", "uses_default_features", True),
            ("nix missing feature", "nix", "features", ["fs", "socket"]),
            ("security extra feature", "security-framework", "features", ["OSX_10_15", "OSX_10_14"]),
            ("floating security", "security-framework", "req", "^3.7"),
            ("floating security sys", "security-framework-sys", "req", "^2.17"),
            ("renamed sha", "sha2", "rename", "digest"),
            ("alternate registry", "libc", "source", "registry+https://example.invalid/index"),
            ("external api path", "runne-api", "path", "/external/runne-api"),
            ("provider wrong target", "runne-provider", "target", None),
            ("provider feature", "runne-provider", "features", ["test-support"]),
            ("provider optional", "runne-provider", "optional", True),
        )
        for label, dependency, field, value in mutations:
            with self.subTest(label=label):
                packages = self.packages()
                selected = packages[0]["dependencies"]
                index = next(
                    index for index, row in enumerate(selected) if row["name"] == dependency
                )
                if field == "delete":
                    del selected[index]
                else:
                    selected[index][field] = value
                self.assertNotEqual(
                    [],
                    architecture.find_macos_process_identity_crate_dependency_violations(
                        packages
                    ),
                )

    @classmethod
    def packages(cls):
        target = 'cfg(target_os = "macos")'
        registry = architecture.CRATES_IO_REGISTRY_SOURCE
        dependencies = [
            cls.dependency("core-foundation", target, "=0.10.1", source=registry),
            cls.dependency("libc", target, "^0.2", source=registry),
            cls.dependency(
                "nix",
                target,
                "=0.31.3",
                features=["fs", "poll", "socket"],
                defaults=False,
                source=registry,
            ),
            cls.dependency("runne-api", target, "*", path="/workspace/crates/runne-api"),
            cls.dependency(
                "runne-provider",
                target,
                "*",
                path="/workspace/crates/runne-provider",
            ),
            cls.dependency(
                "security-framework",
                target,
                "=3.7.0",
                features=["OSX_10_15"],
                source=registry,
            ),
            cls.dependency("security-framework-sys", target, "=2.17.0", source=registry),
            cls.dependency("sha2", target, "=0.10.8", source=registry),
        ]
        return [
            {
                "name": "runne-macos-process-identity",
                "manifest_path": "/workspace/crates/runne-macos-process-identity/Cargo.toml",
                "dependencies": dependencies,
            },
            {
                "name": "runne-api",
                "manifest_path": "/workspace/crates/runne-api/Cargo.toml",
                "dependencies": [],
            },
            {
                "name": "runne-provider",
                "manifest_path": "/workspace/crates/runne-provider/Cargo.toml",
                "dependencies": [],
            },
        ]

    @staticmethod
    def dependency(name, target, req, *, features=None, defaults=True, source=None, path=None):
        return {
            "name": name,
            "kind": None,
            "target": target,
            "req": req,
            "features": features or [],
            "rename": None,
            "optional": False,
            "uses_default_features": defaults,
            "source": source,
            "path": path,
        }
