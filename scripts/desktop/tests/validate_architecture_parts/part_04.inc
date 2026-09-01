
class MacOsProcessIdentityDependencyTest(unittest.TestCase):
    def test_native_enrollment_authority_has_only_approved_neutral_dependencies(self):
        authority = "runne-native-enrollment-authority"
        self.assertEqual(
            {
                "runne-macos-process-identity",
                "runne-provider",
            },
            architecture.ALLOWED_RUST_DEPENDENCIES[authority],
        )
        self.assertIn(
            authority,
            architecture.ALLOWED_RUST_DEPENDENCIES["runne-secure-store"],
        )

    def test_allows_only_the_exact_macos_dependency_target(self):
        def packages(target):
            return [
                {
                    "name": "runne-platform-desktop",
                    "dependencies": [
                        {
                            "name": "runne-macos-process-identity",
                            "target": target,
                        }
                    ],
                }
            ]

        self.assertEqual(
            [],
            architecture.find_macos_process_identity_dependency_violations(
                packages('cfg(target_os = "macos")')
            ),
        )
        for target in (None, "cfg(unix)", 'cfg(target_os = "linux")'):
            with self.subTest(target=target):
                self.assertEqual(
                    [
                        "runne-platform-desktop must depend on "
                        "runne-macos-process-identity only through "
                        'cfg(target_os = "macos")'
                    ],
                    architecture.find_macos_process_identity_dependency_violations(
                        packages(target)
                    ),
                )

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
            ("CLI authority Unix-wide", "cli", 0, "target", "cfg(unix)"),
            ("CLI authority dev-only", "cli", 0, "kind", "dev"),
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
            ("CLI rustix extra feature", "cli", 1, "features", ["fs", "net"]),
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

    @staticmethod
    def native_writer_packages():
        def dependency(name, *, kind=None, target=None, req="*", features=None):
            return {
                "name": name,
                "kind": kind,
                "target": target,
                "req": req,
                "features": features or [],
                "rename": None,
                "optional": False,
                "uses_default_features": True,
            }

        macos = 'cfg(target_os = "macos")'
        return [
            {
                "name": "runne-native-enrollment-authority",
                "dependencies": [
                    dependency("runne-provider"),
                    dependency("runne-macos-process-identity", target=macos),
                ],
            },
            {
                "name": "runne-cli",
                "dependencies": [
                    dependency(
                        "runne-native-enrollment-authority", target=macos
                    ),
                    dependency(
                        "rustix",
                        kind="dev",
                        target=macos,
                        req="=1.1.4",
                        features=["net"],
                    ),
                ],
            },
        ]

    def test_allows_native_enrollment_authority_only_on_the_macos_target(self):
        package = "runne-native-enrollment-authority"
        exact = [
            {
                "name": package,
                "dependencies": [
                    {
                        "name": "runne-macos-process-identity",
                        "target": 'cfg(target_os = "macos")',
                    }
                ],
            }
        ]
        self.assertEqual(
            [],
            architecture.find_macos_process_identity_dependency_violations(exact),
        )
        exact[0]["dependencies"][0]["target"] = None
        self.assertEqual(
            [
                "runne-native-enrollment-authority must depend on "
                "runne-macos-process-identity only through "
                'cfg(target_os = "macos")'
            ],
            architecture.find_macos_process_identity_dependency_violations(exact),
        )

    def test_rejects_any_non_authority_consumer_even_on_the_macos_target(self):
        for package in ("runne-daemon", "runne-cli", "another-consumer"):
            with self.subTest(package=package):
                self.assertEqual(
                    [f"{package} -> runne-macos-process-identity is forbidden"],
                    architecture.find_macos_process_identity_dependency_violations(
                        [
                            {
                                "name": package,
                                "dependencies": [
                                    {
                                        "name": "runne-macos-process-identity",
                                        "target": 'cfg(target_os = "macos")',
                                    }
                                ],
                            }
                        ]
                    ),
                )
