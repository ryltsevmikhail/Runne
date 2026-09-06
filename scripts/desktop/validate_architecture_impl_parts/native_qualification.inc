"""Closed dependency and source boundary for native qualification tickets."""
from __future__ import annotations

NATIVE_QUALIFICATION_PACKAGE = "runne-native-qualification"
NATIVE_QUALIFICATION_DEPENDENCIES = {
    "base64", "ed25519-dalek", "hex", "serde", "serde_json", "sha2",
}
ALLOWED_RUST_DEPENDENCIES[NATIVE_QUALIFICATION_PACKAGE] = set()
NATIVE_QUALIFICATION_EXACT_DEPENDENCIES = {
    ("normal", "base64"): ("=0.22.1", (), True),
    ("normal", "ed25519-dalek"): ("=2.1.1", (), True),
    ("normal", "hex"): ("^0.4", (), True),
    ("normal", "serde"): ("=1.0.229", ("derive",), True),
    ("normal", "serde_json"): ("=1.0.151", (), True),
    ("normal", "sha2"): ("=0.10.8", (), True),
    ("dev", "jsonschema"): ("=0.18.0", ("draft202012",), False),
}
NATIVE_QUALIFICATION_FORBIDDEN_SOURCE = re.compile(
    r"\b(?:std::env|std::fs|std::path|SigningKey|File::|OpenOptions|dyn\s+Fn|impl\s+Fn)\b"
    r"|<\s*[A-Za-z_]\w*\s*:\s*Fn"
    r"|\bwhere\b[^;{]*\bFn(?:Once|Mut)?\s*\("
    r"|\buse\s+std\s*::\s*\{[^}]*\b(?:env|fs|path)\b"
)
NATIVE_QUALIFICATION_PROOF = re.compile(
    r"(?s)(?P<attributes>(?:\s*#\[[^]]+\]\s*)*)pub\s+struct\s+VerifiedQualificationFault\b"
)


def find_native_qualification_dependency_violations(packages: list[dict]) -> list[str]:
    """Require one exact registry edge for every qualification dependency."""
    package = next(
        (row for row in packages if row.get("name") == NATIVE_QUALIFICATION_PACKAGE),
        None,
    )
    if package is None:
        return [f"{NATIVE_QUALIFICATION_PACKAGE} package is missing from workspace metadata"]
    violations = []
    manifest = package.get("manifest_path")
    if (
        not isinstance(manifest, str)
        or Path(manifest).name != "Cargo.toml"
        or Path(manifest).parent.name != NATIVE_QUALIFICATION_PACKAGE
    ):
        violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} manifest_path is noncanonical")
    observed = set()
    for dependency in package.get("dependencies", []):
        name = dependency.get("name", "")
        kind = dependency.get("kind") or "normal"
        key = (kind, name)
        expected = NATIVE_QUALIFICATION_EXACT_DEPENDENCIES.get(key)
        shape = (
            dependency.get("req"),
            tuple(sorted(dependency.get("features", []))),
            dependency.get("uses_default_features", True),
        )
        registry_only = (
            dependency.get("source") == CARGO_REGISTRY_SOURCE
            and dependency.get("path") is None
            and dependency.get("registry") is None
            and dependency.get("target") is None
            and dependency.get("rename") is None
            and dependency.get("optional", False) is False
        )
        if expected is None:
            violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) is forbidden")
        elif key in observed or shape != expected or not registry_only:
            violations.append(
                f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) has forbidden shape"
            )
        observed.add(key)
    for kind, name in sorted(NATIVE_QUALIFICATION_EXACT_DEPENDENCIES.keys() - observed):
        violations.append(f"{NATIVE_QUALIFICATION_PACKAGE} -> {name} ({kind}) is missing")
    return sorted(violations)


def find_native_qualification_violations(root: Path) -> list[str]:
    """Keep runtime key lookup, signing and cloneable proof surfaces out."""
    source_root = root / "crates" / NATIVE_QUALIFICATION_PACKAGE / "src"
    if not source_root.exists():
        return []
    violations = []
    for path in sorted(source_root.rglob("*.rs")):
        if "tests" in path.relative_to(source_root).parts:
            continue
        text = path.read_text(encoding="utf-8")
        if NATIVE_QUALIFICATION_FORBIDDEN_SOURCE.search(text):
            violations.append(f"{path.relative_to(root).as_posix()} has forbidden authority surface")
        match = NATIVE_QUALIFICATION_PROOF.search(text)
        if match and any(
            name in match.group("attributes")
            for name in ("Clone", "Copy", "Serialize", "Deserialize")
        ):
            violations.append(f"{path.relative_to(root).as_posix()} makes verified fault reusable")
    return violations
