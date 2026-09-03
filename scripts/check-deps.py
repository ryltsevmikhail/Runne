#!/usr/bin/env python3
"""Verify runne workspace dependency boundaries."""
import json
import pathlib
import re
import subprocess
import sys

POLICIES = {
    "runne-api": {
        "base64", "ed25519-dalek", "hex", "hmac", "jsonschema", "runne-domain",
        "runne-plugin-protocol", "serde", "serde_json", "sha2", "subtle", "zeroize",
    },
    "runne-domain": {"uuid", "sha2", "hex", "chrono", "serde"},
    "runne-plugin-protocol": set(),
    "runne-observability": {"runne-application"},
    "runne-platform": {"runne-application", "runne-platform-ports", "libc", "thiserror", "uuid"},
    "runne-macos-process-identity": {
        "core-foundation", "libc", "nix", "runne-api", "runne-provider", "security-framework", "security-framework-sys", "sha2",
    },
    "runne-native-enrollment-authority": {
        "runne-api", "runne-macos-process-identity", "runne-provider",
    },
    "runne-project-owner-authority": {
        "argon2", "base64", "chacha20poly1305", "ed25519-dalek", "serde",
        "serde_json", "sha2", "thiserror", "zeroize", "runne-promotion-contracts",
    },
    "runne-promotion-contracts": {"serde", "serde_json", "sha2", "thiserror"},
    "runne-release-authority": {
        "ed25519-dalek",
        "fs2",
        "serde",
        "serde_json",
        "sha2",
        "thiserror",
        "runne-project-owner-authority",
        "runne-promotion-contracts",
    },
}
exec((pathlib.Path(__file__).with_name("check_deps_macos_process_identity.inc")).read_text(encoding="utf-8"))
exec((pathlib.Path(__file__).with_name("check_deps_native_enrollment.inc")).read_text(encoding="utf-8"))

EXACT_VERSION_POLICIES = {
    "runne-project-owner-authority": POLICIES["runne-project-owner-authority"],
    "runne-release-authority": POLICIES["runne-release-authority"],
}
INTERNAL_AUTHORITY_EDGES = {
    ("runne-project-owner-authority", "runne-promotion-contracts"),
    ("runne-release-authority", "runne-project-owner-authority"),
    ("runne-release-authority", "runne-promotion-contracts"),
}
NATIVE_ENROLLMENT_AUTHORITY = "runne-native-enrollment-authority"
NATIVE_ENROLLMENT_AUTHORITY_CONSUMERS = {"runne-cli", "runne-secure-store"}
FORBIDDEN_PROJECT_OWNER_AUTHORITY_EDGES = {
    "runne-cli", "runne-store", "runne-runtime",
}
PROJECT_OWNER_STORE_FEATURE = "project-owner-key-store"
PROJECT_OWNER_STORE_FEATURES = {
    PROJECT_OWNER_STORE_FEATURE,
    "provider-credential-broker-writer",
}
PROJECT_OWNER_STORE_OWNER = "runne-cli"
PROJECT_OWNER_STORE_SYMBOLS = re.compile(
    r"\b(?:PendingProjectOwnerKey|ProjectOwnerAnchorFloor|ProjectOwnerKey\w*|StoreStatus|"
    r"ProjectOwnerKeyStore|project_owner_key(?:_store)?|create_or_resume_pending|"
    r"commit_pending_and_floor|reset_after_compromise|sign_active|activate_pending|"
    r"read_active_ref|read_anchor_floor|write_anchor_floor|export_active_for_backup|"
    r"restore_active|into_backup_seed|validate_transcript|MAX_PROJECT_OWNER_TRANSCRIPT_BYTES)\b"
)
PROJECT_OWNER_STORE_WILDCARD_IMPORT = re.compile(r"\buse\s+runne_secure_store\s*::\s*\*")


def main() -> int:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    metadata = json.loads(result.stdout)
    workspace_manifest = (pathlib.Path(__file__).parents[1] / "Cargo.toml").read_text(encoding="utf-8")

    found: set[str] = set()
    errors: list[str] = []
    if 'argon2 = { version = "=0.5.3", features = ["zeroize"] }' not in workspace_manifest:
        errors.append("FAIL: project-owner authority requires argon2 zeroize feature")

    for pkg in metadata["packages"]:
        name = pkg["name"]
        if name not in POLICIES:
            continue
        found.add(name)

        deps = pkg.get("dependencies", [])
        production_deps = {
            dep["name"]
            for dep in deps
            if dep.get("kind") != "dev"
        }
        disallowed = production_deps - POLICIES[name]
        if disallowed:
            errors.append(
                f"FAIL: {name} has disallowed production dependencies: "
                f"{sorted(disallowed)}"
            )
        if name == "runne-project-owner-authority":
            forbidden = production_deps & FORBIDDEN_PROJECT_OWNER_AUTHORITY_EDGES
            if forbidden:
                errors.append(
                    "FAIL: runne-project-owner-authority has forbidden core edges: "
                    f"{sorted(forbidden)}"
                )
        if name in EXACT_VERSION_POLICIES:
            non_exact = sorted(
                dep["name"]
                for dep in deps
                if dep.get("kind") != "dev"
                and dep["name"] in EXACT_VERSION_POLICIES[name]
                and (name, dep["name"]) not in INTERNAL_AUTHORITY_EDGES
                and not dep["req"].startswith("=")
            )
            if non_exact:
                errors.append(
                    f"FAIL: {name} has non-exact production dependencies: {non_exact}"
                )

    errors.extend(project_owner_store_declaration_errors(metadata["packages"]))
    errors.extend(macos_process_identity_dependency_errors(metadata["packages"]))
    errors.extend(project_owner_store_consumer_errors(metadata["packages"]))
    errors.extend(native_enrollment_authority_consumer_errors(metadata["packages"]))
    errors.extend(release_authority_boundary_errors(metadata["packages"]))
    errors.extend(internal_authority_edge_errors(metadata["packages"]))

    resolved = next(
        (node for node in metadata.get("resolve", {}).get("nodes", [])
         if node["id"].startswith("path+file://") and "/crates/runne-secure-store#" in node["id"]),
        None,
    )
    if resolved is None or PROJECT_OWNER_STORE_FEATURE not in resolved.get("features", []):
        errors.append("FAIL: resolved runne-secure-store feature is missing project-owner-key-store")

    missing = set(POLICIES) - found
    if missing:
        errors.append(f"FAIL: workspace packages not found: {missing}")

    # Check protocol does not depend on domain
    for pkg in metadata["packages"]:
        if pkg["name"] != "runne-plugin-protocol":
            continue
        for dep in pkg.get("dependencies", []):
            if dep["name"] == "runne-domain":
                errors.append("FAIL: runne-plugin-protocol depends on runne-domain")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    print(
        f"OK: {len(found)}/{len(POLICIES)} workspace packages satisfy dependency policies"
    )
    return 0


def project_owner_store_declaration_errors(packages: list[dict]) -> list[str]:
    """Return fail-closed errors for every direct secure-store declaration."""
    errors: list[str] = []
    owners = 0
    for package in packages:
        package_name = package.get("name", "<unknown>")
        for dependency in package.get("dependencies", []):
            if dependency.get("name") != "runne-secure-store":
                continue
            features = set(dependency.get("features", []))
            is_owner = (
                package_name == PROJECT_OWNER_STORE_OWNER
                and dependency.get("kind") is None
                and dependency.get("target") is None
                and dependency.get("rename") is None
                and dependency.get("optional") is False
                and dependency.get("uses_default_features") is False
                and features == PROJECT_OWNER_STORE_FEATURES
                and dependency.get("path", "").endswith("/crates/runne-secure-store")
            )
            if is_owner:
                owners += 1
                continue
            is_test_support_dev_dependency = (
                dependency.get("kind") == "dev"
                and dependency.get("target") is None
                and dependency.get("rename") is None
                and dependency.get("optional") is False
                and dependency.get("uses_default_features") is False
                and features == {"test-support"}
                and dependency.get("path", "").endswith("/crates/runne-secure-store")
            )
            if is_test_support_dev_dependency:
                continue
            if dependency.get("uses_default_features", True):
                errors.append(f"FAIL: {package_name} must disable runne-secure-store default features")
            if package_name == PROJECT_OWNER_STORE_OWNER:
                errors.append("FAIL: runne-cli owner declaration must be normal, unrenamed, nonoptional, untargeted, workspace-path exact-features and default-features=false")
            if features:
                errors.append(f"FAIL: {package_name} must not enable secure-store features")
            if dependency.get("rename") is not None:
                errors.append(f"FAIL: {package_name} must not rename runne-secure-store")
            if dependency.get("target") is not None and PROJECT_OWNER_STORE_FEATURE in features:
                errors.append(f"FAIL: {package_name} must not target-gate project-owner-key-store")
    if owners != 1:
        errors.append(f"FAIL: require exactly one runne-cli project-owner-key-store declaration, found {owners}")
    return errors


def project_owner_store_consumer_errors(packages: list[dict]) -> list[str]:
    """Reject owner-key API mentions outside CLI and secure-store metadata targets."""
    errors: list[str] = []
    for package in packages:
        if package.get("name") in {PROJECT_OWNER_STORE_OWNER, "runne-secure-store"}:
            continue
        manifest = pathlib.Path(package["manifest_path"])
        paths = {manifest}
        for target in package.get("targets", []):
            paths.add(pathlib.Path(target["src_path"]))
        for base in paths.copy():
            if base.suffix == ".rs" and base.parent.exists():
                paths.update(base.parent.rglob("*.rs"))
        for path in sorted(paths):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            if PROJECT_OWNER_STORE_SYMBOLS.search(text) or PROJECT_OWNER_STORE_WILDCARD_IMPORT.search(text):
                errors.append(f"FAIL: forbidden project-owner-store consumer: {path}")
    return errors


def release_authority_boundary_errors(packages: list[dict]) -> list[str]:
    """Require the promotion engine to remain CLI-only and secret-store-free."""
    errors: list[str] = []
    consumers = {
        package["name"]
        for package in packages
        if any(
            dependency["name"] == "runne-release-authority"
            and dependency.get("kind") != "dev"
            for dependency in package.get("dependencies", [])
        )
    }
    if consumers != {"runne-cli"}:
        errors.append(
            "FAIL: runne-release-authority must be consumed only by runne-cli; "
            f"found {sorted(consumers)}"
        )
    authority = next((package for package in packages if package["name"] == "runne-release-authority"), None)
    if authority is None:
        return errors
    sources = pathlib.Path(authority["manifest_path"]).parent / "src"
    if any("runne_secure_store" in path.read_text(encoding="utf-8") for path in sources.rglob("*.rs")):
        errors.append("FAIL: runne-release-authority must not import runne-secure-store APIs")
    return errors


def internal_authority_edge_errors(packages: list[dict]) -> list[str]:
    """Require declared authority-internal crates to be normal local dependencies."""
    errors: list[str] = []
    for package in packages:
        owner = package.get("name")
        for dependency in package.get("dependencies", []):
            edge = (owner, dependency.get("name"))
            if edge not in INTERNAL_AUTHORITY_EDGES:
                continue
            path = dependency.get("path", "")
            valid = (
                dependency.get("kind") is None and dependency.get("target") is None
                and dependency.get("rename") is None and not dependency.get("optional")
                and path.endswith(f"/crates/{edge[1]}")
            )
            if not valid:
                errors.append(f"FAIL: invalid internal authority edge: {owner} -> {edge[1]}")
    return errors


if __name__ == "__main__":
    sys.exit(main())
