
class MacOsProcessIdentityDependencyTest(unittest.TestCase):
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

    def test_rejects_any_non_desktop_consumer_even_on_the_macos_target(self):
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
