use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/installed_surface_audit.rs"]
mod installed_surface_audit;
#[path = "support/installed_surface_consumers.rs"]
mod installed_surface_consumers;
#[path = "support/installed_surface_daemon.rs"]
mod installed_surface_daemon;
#[path = "support/installed_surface_expected.rs"]
mod installed_surface_expected;
#[path = "support/installed_surface_macros.rs"]
mod installed_surface_macros;
#[path = "support/installed_surface_syntax.rs"]
mod installed_surface_syntax;

use installed_surface_audit::audit_sources;

#[path = "support/installed_transfer_tests.rs"]
mod installed_transfer_tests;

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
        (
            audit.factory,
            audit.verification,
            audit.retention,
            audit.initial_result,
            audit.facts_reexports,
        ),
        (1, 1, 1, 1, 3),
        "{:#?}",
        audit.violations,
    );
    assert!(audit.violations.is_empty(), "{:#?}", audit.violations);
}

#[test]
fn adversarial_alias_generic_trait_and_wrapper_escapes_are_rejected() {
    let baseline = baseline();
    assert!(
        audit_sources(&[(installed_surface_daemon::DAEMON_SOURCE, &baseline)])
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
            "pub(crate) struct VerifiedQualificationAdmission",
            "#[cfg_attr(test, derive(Default))] pub(crate) struct VerifiedQualificationAdmission",
        ),
        baseline.replace(
            "_admission: runne_native_qualification::PendingQualificationAdmission",
            "pub _admission: runne_native_qualification::PendingQualificationAdmission",
        ),
        format!(
            "{baseline}\nimpl VerifiedQualificationAdmission {{ pub fn from_admission(admission: runne_native_qualification::PendingQualificationAdmission) -> Self {{ Self {{ _admission: admission }} }} }}"
        ),
        format!(
            "{baseline}\nimpl VerifiedQualificationAdmission {{ pub fn admission(&self) -> &runne_native_qualification::PendingQualificationAdmission {{ &self._admission }} }}"
        ),
        format!(
            "{baseline}\nfn encode_downstream(_: VerifiedQualificationAdmission) -> Vec<u8> {{ todo!() }}"
        ),
        format!("{baseline}\ntype CarrierAlias = VerifiedQualificationAdmission;"),
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
            "{baseline}\nfn pair_marker_with_carrier(_: QualificationAdmissionError, _: runne_native_qualification::PendingQualificationAdmission) -> VerifiedQualificationAdmission {{ todo!() }}"
        ),
        format!(
            "{baseline}\nunsafe extern \"Rust\" {{ fn consume_facts(_: *const VerifiedInstalledEnrollmentMeasurementFacts); }}"
        ),
    ] {
        assert!(
            !audit_sources(&[(installed_surface_daemon::DAEMON_SOURCE, &mutation,)])
                .violations
                .is_empty()
        );
    }
}

#[test]
fn adversarial_macro_definitions_and_invocations_cannot_generate_authority_surfaces() {
    let baseline = baseline();
    let mutations = [
        format!(
            "{baseline}\nmacro_rules! forge {{ () => {{ impl VerifiedQualificationAdmission {{ pub fn admission(&self) -> &runne_native_qualification::PendingQualificationAdmission {{ &self._admission }} }} }} }} forge!();"
        ),
        format!(
            "{baseline}\nmacro_rules! relay {{ ($carrier:ty) => {{ fn encode(_: $carrier) -> Vec<u8> {{ todo!() }} }} }} relay!(VerifiedQualificationAdmission);"
        ),
        format!(
            "{baseline}\nmod nested {{ macro_rules! build {{ () => {{ fn construct(_: PendingQualificationAdmission) -> VerifiedQualificationAdmission {{ todo!() }} }} }} build!(); }}"
        ),
        format!(
            "{baseline}\ncrate::authority::generate!(VerifiedInstalledEnrollmentMeasurementFacts);"
        ),
        format!(
            "{baseline}\nmod nested {{ pub mod authority {{ macro_rules! generate {{ ($type:ty) => {{ fn encode(_: $type) -> Vec<u8> {{ todo!() }} }} }} pub(crate) use generate; }} }} nested::authority::generate!(VerifiedQualificationAdmission);"
        ),
        format!("{baseline}\nuse crate::VerifiedQualificationAdmission as Gate; authority!(Gate);"),
    ];
    for mutation in mutations {
        assert!(
            !audit_sources(&[(installed_surface_daemon::DAEMON_SOURCE, &mutation)])
                .violations
                .is_empty(),
            "macro authority surface escaped recursive audit"
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
    initial_baseline().replace(
        "struct VerifiedQualificationAdmission",
        "pub(crate) struct VerifiedQualificationAdmission",
    )
}

fn initial_baseline() -> String {
    "pub struct VerifiedInstalledEnrollmentMeasurementFacts { candidate: [u8; 32] }\nstruct QualificationRuntimeInstalledExpectation { candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32] }\n#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] struct VerifiedQualificationAdmission { _admission: runne_native_qualification::PendingQualificationAdmission, owned: Box<runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3>, members: qualification_fence::QualificationAdmissionMembers }\n#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] enum InitialQualificationFrame { Legacy(Zeroizing<Vec<u8>>), Verified(VerifiedQualificationAdmission), }\nstruct InstalledExpectationError; struct QualificationAdmissionError; struct LaunchAuthorityError;\nimpl VerifiedInstalledEnrollmentMeasurementFacts { fn qualification_runtime_installed_expectation(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3) -> Result<QualificationRuntimeInstalledExpectation, InstalledExpectationError> { todo!() } pub fn verify_qualification_admission(&self, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: &runne_native_qualification::PendingQualificationAdmission, now_unix_seconds: u64) -> Result<(), QualificationAdmissionError> { todo!() } }\n#[cfg(all(target_os = \"macos\", target_arch = \"aarch64\"))] fn verify_and_retain_qualification_admission(installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts, owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3, verifier: &mut runne_native_qualification::QualificationAdmissionVerifier, admission: runne_native_qualification::PendingQualificationAdmission, members: qualification_fence::QualificationAdmissionMembers, now_unix_seconds: u64) -> Result<VerifiedQualificationAdmission, LaunchAuthorityError> { todo!() }".into()
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
