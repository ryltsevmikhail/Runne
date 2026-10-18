
class NativeWriterBootstrapDependencyTest(unittest.TestCase):
    def test_native_writer_dependencies_require_exact_edges(self):
        self.assertEqual(
            [],
            architecture.find_native_writer_bootstrap_dependency_violations(
                self.native_writer_packages()
            ),
        )

    def test_rejects_native_writer_dependency_mutations(self):
        mutations = (
            ("authority provider deleted", "authority", 0, "delete", None),
            ("authority extra edge", "authority", 0, "name", "runne-api"),
            ("authority low-level wrong target", "authority", 1, "target", None),
            ("authority low-level dev-only", "authority", 1, "kind", "dev"),
            ("CLI authority deleted", "cli", 0, "delete", None),
            ("CLI authority macOS-only", "cli", 0, "target", 'cfg(target_os = "macos")'),
            ("CLI authority Linux-only", "cli", 0, "target", 'cfg(target_os = "linux")'),
            ("CLI authority Unix-wide", "cli", 0, "target", "cfg(unix)"),
            ("CLI authority dev-only", "cli", 0, "kind", "dev"),
            ("CLI authority wrong local path", "cli", 0, "path", "/workspace/impostor"),
            (
                "CLI direct low-level edge",
                "cli",
                0,
                "name",
                "runne-macos-process-identity",
            ),
            ("CLI rustix production", "cli", 1, "kind", None),
            ("CLI rustix Unix-wide", "cli", 1, "target", "cfg(unix)"),
            ("CLI rustix floating", "cli", 1, "req", "^1"),
            (
                "CLI rustix alternate registry",
                "cli",
                1,
                "source",
                "registry+https://example.invalid/index",
            ),
            ("CLI rustix extra feature", "cli", 1, "features", ["fs", "net"]),
            ("CLI rustix IO deleted", "cli", 2, "delete", None),
            ("CLI rustix IO unguarded", "cli", 2, "target", None),
            ("CLI rustix IO Unix-wide", "cli", 2, "target", "cfg(unix)"),
            ("CLI rustix IO macOS-only", "cli", 2, "target", 'cfg(target_os = "macos")'),
            ("CLI rustix IO dev-only", "cli", 2, "kind", "dev"),
            ("CLI rustix IO wrong feature set", "cli", 2, "features", ["fs", "net"]),
            ("CLI rustix IO floating req", "cli", 2, "req", "^1.1"),
            ("CLI rustix IO default features", "cli", 2, "uses_default_features", True),
        )
        for label, package, index, key, value in mutations:
            with self.subTest(label=label):
                packages = self.native_writer_packages()
                selected = packages[0 if package == "authority" else 1]["dependencies"]
                if key == "delete":
                    del selected[index]
                else:
                    selected[index][key] = value
                self.assertNotEqual(
                    [],
                    architecture.find_native_writer_bootstrap_dependency_violations(
                        packages
                    ),
                )

    def test_rejects_extra_cli_rustix_edge(self):
        packages = self.native_writer_packages()
        cli = packages[1]["dependencies"]
        cli.append(dict(cli[2]))
        self.assertEqual(
            [
                "runne-cli must have exactly two rustix dependency edges",
                'runne-cli must have one exact rustix edge for regular '
                'cfg(target_os = "linux")',
            ],
            architecture.find_native_writer_bootstrap_dependency_violations(packages),
        )

    def test_rejects_unapproved_authority_normal_dependencies_and_sources(self):
        for dependency in (
            self.dependency("libc", req="^0.2", source="registry+crates.io"),
            self.dependency("nix", req="^0.31", source="registry+crates.io"),
        ):
            with self.subTest(dependency=dependency["name"]):
                packages = self.native_writer_packages()
                packages[0]["dependencies"].append(dependency)
                self.assertNotEqual(
                    [],
                    architecture.find_native_writer_bootstrap_dependency_violations(
                        packages
                    ),
                )

        for label, key, value in (
            ("provider registry substitution", "source", "registry+crates.io"),
            ("provider wrong local path", "path", "/workspace/crates/impostor"),
            ("macOS identity registry substitution", "source", "registry+crates.io"),
            ("macOS identity wrong local path", "path", "/workspace/crates/impostor"),
        ):
            with self.subTest(label=label):
                packages = self.native_writer_packages()
                index = 1 if label.startswith("macOS") else 0
                packages[0]["dependencies"][index][key] = value
                self.assertNotEqual(
                    [],
                    architecture.find_native_writer_bootstrap_dependency_violations(
                        packages
                    ),
                )

    @staticmethod
    def native_writer_packages():
        macos = 'cfg(target_os = "macos")'
        writer = 'cfg(any(target_os = "macos", target_os = "linux"))'
        return [
            {
                "name": "runne-native-enrollment-authority",
                "manifest_path": "/workspace/crates/runne-native-enrollment-authority/Cargo.toml",
                "dependencies": [
                    NativeWriterBootstrapDependencyTest.dependency(
                        "runne-provider",
                        path="/workspace/crates/../crates/runne-provider",
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "runne-macos-process-identity", target=macos
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "runne-api", target=macos
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "rustix", target='cfg(target_os = "linux")',
                        req="=1.1.4", features=["net", "process"],
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "sha2", target='cfg(target_os = "linux")',
                        req="=0.10.8",
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "serde",
                        kind="dev",
                        req="=1.0.229",
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "syn",
                        kind="dev",
                        req="^2",
                        features=["full", "visit"],
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                ],
            },
            {
                "name": "runne-cli",
                "manifest_path": "/workspace/crates/runne-cli/Cargo.toml",
                "dependencies": [
                    NativeWriterBootstrapDependencyTest.dependency(
                        "runne-native-enrollment-authority", target=writer
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "rustix",
                        kind="dev",
                        target=writer,
                        req="=1.1.4",
                        features=["net", "pipe", "process"],
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                    NativeWriterBootstrapDependencyTest.dependency(
                        "rustix",
                        target='cfg(target_os = "linux")',
                        req="=1.1.4",
                        features=["fs", "process"],
                        uses_default_features=False,
                        source=architecture.CRATES_IO_REGISTRY_SOURCE,
                    ),
                ],
            },
            {
                "name": "runne-provider",
                "manifest_path": "/workspace/crates/runne-provider/Cargo.toml",
                "dependencies": [],
            },
            {
                "name": "runne-api",
                "manifest_path": "/workspace/crates/runne-api/Cargo.toml",
                "dependencies": [],
            },
            {
                "name": "runne-macos-process-identity",
                "manifest_path": "/workspace/crates/runne-macos-process-identity/Cargo.toml",
                "dependencies": [],
            },
        ]

    @staticmethod
    def dependency(
        name,
        *,
        kind=None,
        target=None,
        req="*",
        features=None,
        source=None,
        path=None,
        uses_default_features=True,
    ):
        if path is None and name.startswith("runne-"):
            path = f"/workspace/crates/{name}"
        return {
            "name": name,
            "kind": kind,
            "target": target,
            "req": req,
            "features": features or [],
            "rename": None,
            "optional": False,
            "uses_default_features": uses_default_features,
            "source": source,
            "path": path,
        }
