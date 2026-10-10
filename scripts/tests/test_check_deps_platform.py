import importlib.util
import pathlib
import sys
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "check-deps.py"
SPEC = importlib.util.spec_from_file_location("check_deps_platform", SCRIPT_PATH)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def platform_package(dependencies: list[dict]) -> dict:
    """Return a runne-platform metadata package with `dependencies`."""
    return {"name": "runne-platform", "dependencies": dependencies}


def production(name: str, req: str = "*") -> dict:
    """Return a production dependency edge shaped like cargo metadata."""
    return {"name": name, "kind": None, "req": req}


def approved_platform_dependencies() -> list[dict]:
    """Return the reviewed production edge set allowed for runne-platform."""
    return [production(name) for name in sorted(checker.POLICIES["runne-platform"])]


class RunnePlatformPolicyTests(unittest.TestCase):
    def test_approves_the_reviewed_production_edge_set(self) -> None:
        errors, found = checker.package_policy_errors(
            [platform_package(approved_platform_dependencies())]
        )
        self.assertEqual(errors, [])
        self.assertEqual(found, {"runne-platform"})

    def test_rejects_unapproved_internal_and_unknown_production_deps(self) -> None:
        for name in ("runne-store", "runne-runtime", "tokio", "serde_yaml"):
            with self.subTest(dependency=name):
                dependencies = approved_platform_dependencies() + [production(name)]
                errors, _ = checker.package_policy_errors(
                    [platform_package(dependencies)]
                )
                self.assertEqual(
                    errors,
                    [
                        "FAIL: runne-platform has disallowed production "
                        f"dependencies: ['{name}']"
                    ],
                )

    def test_dev_dependencies_are_not_production_edges(self) -> None:
        dependencies = approved_platform_dependencies() + [
            {"name": "runne-store", "kind": "dev", "req": "*"},
            {"name": "serde_json", "kind": "dev", "req": "*"},
        ]
        self.assertEqual(
            checker.package_policy_errors([platform_package(dependencies)])[0], []
        )

    def test_new_names_stay_rejected_for_other_policed_crates(self) -> None:
        for crate, names in (
            ("runne-plugin-protocol", ["serde", "serde_json", "base64", "runne-domain"]),
            ("runne-api", ["runne-store", "tokio"]),
        ):
            for name in names:
                if name in checker.POLICIES[crate]:
                    continue
                with self.subTest(crate=crate, dependency=name):
                    errors, _ = checker.package_policy_errors(
                        [{"name": crate, "dependencies": [production(name)]}]
                    )
                    self.assertEqual(
                        errors,
                        [
                            f"FAIL: {crate} has disallowed production "
                            f"dependencies: ['{name}']"
                        ],
                    )

    def test_unknown_packages_are_ignored_and_missing_stay_missing(self) -> None:
        errors, found = checker.package_policy_errors(
            [
                {"name": "runne-cli", "dependencies": [production("serde")]},
                platform_package(approved_platform_dependencies()),
            ]
        )
        self.assertEqual(errors, [])
        self.assertEqual(found, {"runne-platform"})
        self.assertIn("runne-platform", checker.POLICIES)
        self.assertNotIn("runne-cli", checker.POLICIES)

    def test_authority_exact_versions_and_forbidden_edges_still_enforced(self) -> None:
        exact = [
            production(name, req="=1")
            for name in checker.POLICIES["runne-release-authority"]
        ]
        self.assertEqual(
            checker.package_policy_errors(
                [{"name": "runne-release-authority", "dependencies": exact}]
            )[0],
            [],
        )
        non_exact = [production("serde", req="^1")]
        self.assertEqual(
            checker.package_policy_errors(
                [{"name": "runne-release-authority", "dependencies": non_exact}]
            )[0],
            ["FAIL: runne-release-authority has non-exact production "
             "dependencies: ['serde']"],
        )
        internal_edge = [production("runne-promotion-contracts", req="^0.1")]
        self.assertEqual(
            checker.package_policy_errors(
                [{"name": "runne-release-authority", "dependencies": internal_edge}]
            )[0],
            [],
        )
        owner = [
            production(name, req="=1")
            for name in checker.POLICIES["runne-project-owner-authority"]
        ] + [production("runne-store", req="=1")]
        self.assertEqual(
            checker.package_policy_errors(
                [{"name": "runne-project-owner-authority", "dependencies": owner}]
            )[0],
            [
                "FAIL: runne-project-owner-authority has disallowed production "
                "dependencies: ['runne-store']",
                "FAIL: runne-project-owner-authority has forbidden core edges: "
                "['runne-store']",
            ],
        )


if __name__ == "__main__":
    unittest.main()
