use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/installed_surface_audit.rs"]
mod installed_surface_audit;
#[path = "support/installed_surface_consumers.rs"]
mod installed_surface_consumers;
#[path = "support/installed_surface_expected.rs"]
mod installed_surface_expected;
#[path = "support/installed_surface_syntax.rs"]
mod installed_surface_syntax;

use installed_surface_audit::audit_sources;

#[test]
fn production_installed_authority_surface_is_recursively_sealed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap();
    let mut sources = Vec::new();
    collect(&root, &mut sources);
    let owned: Vec<_> = sources
        .iter()
        .map(|path| {
            (
                path.strip_prefix(&root).unwrap().display().to_string(),
                fs::read_to_string(path).unwrap(),
            )
        })
        .collect();
    let borrowed: Vec<_> = owned
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect();
    let audit = audit_sources(&borrowed);
    assert_eq!((audit.facts, audit.expectation, audit.verified), (1, 1, 1));
    assert_eq!(
        (audit.factory, audit.verification, audit.facts_reexports),
        (1, 1, 6),
        "{:#?}",
        audit.violations,
    );
    assert!(audit.violations.is_empty(), "{:#?}", audit.violations);
}

#[test]
fn adversarial_alias_generic_trait_and_wrapper_escapes_are_rejected() {
    let baseline = baseline();
    assert!(
        audit_sources(&[("baseline.rs", &baseline)])
            .violations
            .is_empty()
    );
    for mutation in [
        format!("{baseline}\npub type Leak<T = QualificationRuntimeInstalledExpectation> = T;"),
        format!(
            "{baseline}\npub trait Leak {{ type Output: Into<QualificationRuntimeInstalledExpectation>; }}"
        ),
        format!(
            "{baseline}\nuse crate::QualificationRuntimeInstalledExpectation as Gate; pub fn leak() -> Gate {{ todo!() }}"
        ),
        format!("{baseline}\npub struct Wrap<T: Into<VerifiedQualificationAdmission>>(T);"),
        baseline.replace(
            "candidate_sha256: [u8; 32]",
            "pub candidate_sha256: [u8; 32]",
        ),
        baseline.replace(
            "struct QualificationRuntimeInstalledExpectation",
            "#[derive(Debug)] struct QualificationRuntimeInstalledExpectation",
        ),
        format!(
            "{baseline}\nimpl QualificationRuntimeInstalledExpectation {{ pub fn matches(&self) -> bool {{ true }} }}"
        ),
        format!(
            "{baseline}\npub use crate::QualificationRuntimeInstalledExpectation as PublicGate;"
        ),
        format!("{baseline}\npub type FactsAlias = VerifiedInstalledEnrollmentMeasurementFacts;"),
        format!(
            "{baseline}\nimpl VerifiedInstalledEnrollmentMeasurementFacts {{ pub fn from_fake() -> Self {{ todo!() }} }}"
        ),
        format!(
            "{baseline}\nimpl VerifiedInstalledEnrollmentMeasurementFacts {{ pub fn is_qualified(&self) -> bool {{ true }} }}"
        ),
        format!(
            "{baseline}\nimpl VerifiedInstalledEnrollmentMeasurementFacts {{ pub fn raw_v3_tuple(&self) -> [u8; 32] {{ [0; 32] }} }}"
        ),
        format!(
            "{baseline}\nimpl VerifiedInstalledEnrollmentMeasurementFacts {{ pub const fn test_only_qualification_facts(release: [u8; 32], qualification: [u8; 32], candidate: [u8; 32], raw_v3_tuple: [u8; 32]) -> Self {{ todo!() }} }}"
        ),
        baseline.replace(
            "pub struct VerifiedInstalledEnrollmentMeasurementFacts",
            "#[derive(Clone)] pub struct VerifiedInstalledEnrollmentMeasurementFacts",
        ),
        baseline.replace(
            "struct QualificationRuntimeInstalledExpectation",
            "#[derive(Default)] struct QualificationRuntimeInstalledExpectation",
        ),
        baseline.replace(
            "pub struct VerifiedQualificationAdmission",
            "#[cfg_attr(test, derive(Default))] pub struct VerifiedQualificationAdmission",
        ),
        format!(
            "{baseline}\npub mod nested {{ use super::QualificationRuntimeInstalledExpectation as Gate; pub struct Leak(pub Gate); }}"
        ),
        format!(
            "{baseline}\npub mod outer {{ pub mod inner {{ use super::super::VerifiedQualificationAdmission as Gate; pub trait Leak {{ type Output: Into<Gate>; }} }} }}"
        ),
        format!(
            "{baseline}\npub mod nested {{ use super::QualificationRuntimeInstalledExpectation as Gate; pub use Gate as PublicGate; }}"
        ),
        format!(
            "{baseline}\nunsafe extern \"Rust\" {{ fn forge() -> VerifiedQualificationAdmission; }}"
        ),
        format!(
            "{baseline}\nunsafe extern \"Rust\" {{ fn consume(_: QualificationRuntimeInstalledExpectation); }}"
        ),
        format!(
            "{baseline}\nuse crate::VerifiedQualificationAdmission as Gate; unsafe extern \"Rust\" {{ fn forge_alias() -> Gate; }}"
        ),
        format!(
            "{baseline}\nunsafe extern \"Rust\" {{ fn consume_facts(_: *const VerifiedInstalledEnrollmentMeasurementFacts); }}"
        ),
    ] {
        assert!(
            !audit_sources(&[("mutation.rs", &mutation)])
                .violations
                .is_empty()
        );
    }
}

#[test]
fn reviewed_consumer_path_does_not_exempt_a_new_escape() {
    let source = format!(
        "{}\npub fn leak(_: VerifiedInstalledEnrollmentMeasurementFacts) {{}}",
        baseline()
    );
    let audit = audit_sources(&[(
        "runne-daemon/src/application/provider_credential_enrollment/control_facade/protected_session/claim_runtime.rs",
        &source,
    )]);
    assert!(!audit.violations.is_empty());
}

fn baseline() -> String {
    "pub struct VerifiedInstalledEnrollmentMeasurementFacts { candidate: [u8; 32] }\nstruct QualificationRuntimeInstalledExpectation { candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32] }\npub struct VerifiedQualificationAdmission { private: () }\nstruct InstalledExpectationError; struct QualificationAdmissionError;\nimpl VerifiedInstalledEnrollmentMeasurementFacts { fn qualification_runtime_installed_expectation(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3) -> Result<QualificationRuntimeInstalledExpectation, InstalledExpectationError> { todo!() } pub fn verify_qualification_admission(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: runne_native_qualification::PendingQualificationAdmission, now_unix_seconds: u64) -> Result<VerifiedQualificationAdmission, QualificationAdmissionError> { todo!() } }".into()
}

fn collect(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}
