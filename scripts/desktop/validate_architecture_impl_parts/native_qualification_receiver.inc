"""Exact private provider receiver exception for qualification verification."""
from __future__ import annotations

PROVIDER_QUALIFICATION_RECEIVER_SOURCE = Path(
    "crates/runne-provider/src/credential/enrollment/protocol/"
    "session_attestation/qualified/receiver.rs"
)
PROVIDER_QUALIFICATION_RECEIVER_TEST_SOURCES = {
    Path("crates/runne-provider/src/credential/enrollment/protocol/session_attestation_tests/qualification_admission.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol/session_attestation_tests/qualification_receiver.rs"),
}
PROVIDER_QUALIFICATION_ALLOWED_SOURCES = PROVIDER_QUALIFICATION_RECEIVER_TEST_SOURCES | {
    PROVIDER_QUALIFICATION_RECEIVER_SOURCE,
    Path("crates/runne-provider/src/credential/enrollment/protocol/session_attestation_tests.rs"),
    Path("crates/runne-provider/src/credential/enrollment/protocol/session_attestation_tests/qualification.rs"),
}
PROVIDER_QUALIFICATION_RAW_FACTORY = re.compile(
    r"(?s)pub(?:\([^)]*\))?\s+fn\s+\w+\s*\([^)]*"
    r"(?:candidate_sha256|raw_v3_tuple_sha256)"
)
PROVIDER_WRITER_FAULT_TRANSITION = re.compile(
    r"\bverify_exact_writer_fault_borrowed\b"
)
SERVICE_FAULT_TRANSITION = re.compile(
    r"\bverify_exact_service_fault_borrowed\b"
)
NATIVE_WRITER_FAULT_TRANSITION_SOURCES = {
    Path("crates/runne-native-qualification/src/admission.rs"): 1,
    Path("crates/runne-native-qualification/src/admission_verification.rs"): 2,
    Path("crates/runne-native-qualification/src/tests/admission_verification/writer.rs"): 3,
    Path("crates/runne-native-qualification/tests/support/authority_surface_expected.rs"): 3,
    Path("crates/runne-native-qualification/tests/support/pending_surface_allowlist.rs"): 2,
}
NATIVE_SERVICE_FAULT_TRANSITION_SOURCES = {
    Path("crates/runne-native-qualification/src/admission.rs"): 1,
    Path("crates/runne-native-qualification/src/admission_verification.rs"): 2,
    Path("crates/runne-native-qualification/src/tests/admission_verification/service.rs"): 2,
    Path("crates/runne-native-qualification/tests/support/authority_surface_expected.rs"): 3,
    Path("crates/runne-native-qualification/tests/support/pending_surface_allowlist.rs"): 2,
}


def native_writer_fault_transition_violations(root: Path) -> list[str]:
    """Allow the Writer transition token only at exact native implementation/test sites."""
    crate_root = root / "crates/runne-native-qualification"
    if not crate_root.exists():
        return []
    violations = []
    for path in native_qualification_sources(crate_root):
        relative = path.relative_to(root)
        count = len(PROVIDER_WRITER_FAULT_TRANSITION.findall(path.read_text(encoding="utf-8")))
        expected = NATIVE_WRITER_FAULT_TRANSITION_SOURCES.get(relative, 0)
        if count != expected and (count or expected):
            violations.append(
                f"{relative.as_posix()} has non-exact native Writer transition surface"
            )
    return violations


def native_service_fault_transition_violations(root: Path) -> list[str]:
    """Allow the Service transition token only at exact native implementation/test sites."""
    crate_root = root / "crates/runne-native-qualification"
    if not crate_root.exists():
        return []
    violations = []
    for path in native_qualification_sources(crate_root):
        relative = path.relative_to(root)
        count = len(SERVICE_FAULT_TRANSITION.findall(path.read_text(encoding="utf-8")))
        expected = NATIVE_SERVICE_FAULT_TRANSITION_SOURCES.get(relative, 0)
        if count != expected and (count or expected):
            violations.append(
                f"{relative.as_posix()} has non-exact native Service transition surface"
            )
    return violations


def external_service_fault_transition_violations(root: Path, roots: tuple[Path, ...]) -> list[str]:
    """Reject Service verification calls before the reviewed sole-service owner exists."""
    service_roots = set(roots)
    service_roots.update((root / "crates").glob("*/src"))
    service_roots.update((root / "apps").glob("*/src"))
    violations = []
    for source_root in sorted(service_roots):
        if not source_root.exists():
            continue
        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or path.suffix not in {".inc", ".rs", ".ts", ".tsx", ".vue"}:
                continue
            relative = path.relative_to(root)
            if relative.parts[:2] == ("crates", NATIVE_QUALIFICATION_PACKAGE):
                continue
            if SERVICE_FAULT_TRANSITION.search(path.read_text(encoding="utf-8")):
                violations.append(
                    f"{relative.as_posix()} calls Service fault verification before its sole service owner"
                )
    return violations


def native_qualification_sources(crate_root: Path) -> list[Path]:
    """Return every executable Rust source part subject to native transition counts."""
    return sorted(path for path in crate_root.rglob("*") if path.is_file() and path.suffix in {".inc", ".rs"})


def provider_qualification_surface_violation(relative: Path, source: str) -> str | None:
    """Keep combined verification in one callback-free private provider module."""
    transition_calls = PROVIDER_WRITER_FAULT_TRANSITION.findall(source)
    if transition_calls and (
        relative != PROVIDER_QUALIFICATION_RECEIVER_SOURCE or len(transition_calls) != 1
    ):
        return "calls Writer fault verification outside the sole private receiver"
    imports_native_receiver = re.search(
        r"PendingQualification|Qualification\w*Verifier|Qualification\w*Relay|RawQualification",
        source,
    )
    if "runne-provider" not in relative.parts or not imports_native_receiver:
        return None
    if relative in PROVIDER_QUALIFICATION_RECEIVER_TEST_SOURCES:
        return None
    if relative != PROVIDER_QUALIFICATION_RECEIVER_SOURCE:
        return "exceeds provider facts-only native edge"
    if NATIVE_QUALIFICATION_FORBIDDEN_SOURCE.search(source):
        return "exposes forbidden receiver authority surface"
    if PROVIDER_QUALIFICATION_RAW_FACTORY.search(source):
        return "exposes caller-supplied receiver facts"
    return None
