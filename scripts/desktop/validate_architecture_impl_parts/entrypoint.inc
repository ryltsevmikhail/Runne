"""Remaining architecture helpers and command entrypoint."""


def _direct_dynamic_constructor_pattern(module: str, member: str) -> re.Pattern:
    return re.compile(
        rf"""\bnew\s+(?:\(\s*)?(?:\(\s*)?(?:await\s+)?import\(
            \s*["']{re.escape(module)}["']\s*\)(?:\s*\))?\s*(?:
            \?\.\s*(?:{re.escape(member)}|\[\s*["']{re.escape(member)}["']\s*\])|
            \.\s*{re.escape(member)}|\[\s*["']{re.escape(member)}["']\s*\])(?:\s*\))?\s*\(""",
        re.DOTALL | re.VERBOSE,
    )


def _is_conversation_entity_api(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root / CONVERSATION_ENTITY_API)
        return True
    except ValueError:
        return False


def load_workspace_dependencies(root: Path) -> dict[str, set[str]]:
    metadata = load_workspace_metadata(root)
    return {
        package["name"]: {
            dependency["name"]
            for dependency in package["dependencies"]
            if _tracked_dependency(package["name"], dependency)
        }
        for package in metadata["packages"]
        if package["name"] in ALLOWED_RUST_DEPENDENCIES
    }


def load_workspace_metadata(root: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    metadata = load_workspace_metadata(root)
    dependencies = {
        package["name"]: {
            dependency["name"]
            for dependency in package["dependencies"]
            if _tracked_dependency(package["name"], dependency)
        }
        for package in metadata["packages"]
        if package["name"] in ALLOWED_RUST_DEPENDENCIES
    }
    violations = find_rust_dependency_violations(dependencies)
    violations += find_renderer_conversation_violations(root)
    violations += find_provider_terminal_persistence_violations(root)
    violations += find_provider_terminal_test_feature_violations(metadata["packages"])
    violations += find_protected_admission_surface_violations(root)
    violations += find_credential_publication_signer_violations(root)
    violations += find_macos_process_identity_dependency_violations(metadata["packages"])
    violations += find_macos_process_identity_crate_dependency_violations(metadata["packages"])
    violations += find_native_writer_bootstrap_dependency_violations(metadata["packages"])
    if violations:
        for violation in violations:
            print(f"ERROR: {violation}")
        return 1
    print("Rust and renderer dependency boundaries passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
