
class MacOsProcessIdentityDependencyTest(unittest.TestCase):
    def test_native_enrollment_authority_has_only_approved_neutral_dependencies(self):
        authority = "runne-native-enrollment-authority"
        self.assertEqual(
            {
                "runne-api",
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
