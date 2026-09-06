#[path = "support/authority_surface_audit.rs"]
mod authority_surface_audit;
#[path = "support/authority_use_audit.rs"]
mod authority_use_audit;

use std::path::Path;

use authority_surface_audit::{audit_crate, audit_sources};

const BASELINE: &str = r"
/// Verified context.
pub struct VerifiedQualificationRunContext { id: [u8; 32] }
impl VerifiedQualificationRunContext {
  pub const fn context_id(&self) -> [u8; 32] { self.id }
  pub const fn nonce(&self) -> [u8; 32] { self.id }
  pub const fn expires_at(&self) -> u64 { 0 }
  pub const fn ticket_sha256(&self) -> [u8; 32] { self.id }
}
/// Pending pair.
pub struct PendingQualificationAdmission { inner: Vec<u8> }
impl PendingQualificationAdmission { pub fn from_admitted_bundle(bytes: Vec<u8>) -> Result<Self, QualificationAdmissionError> { todo!() } }
/// Verifier.
pub struct QualificationRunContextVerifier { key: K }
impl QualificationRunContextVerifier {
  pub fn from_compiled_policy() -> Self { todo!() }
  pub fn verify_and_consume(&mut self, bytes: &[u8], expected: &QualificationRunContextExpectation, now_unix_seconds: u64) -> Result<VerifiedQualificationRunContext, QualificationRunContextError> { todo!() }
}
";

#[test]
fn production_context_authorities_have_no_raw_or_reusable_escape_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = audit_crate(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn surface_auditor_rejects_alias_trait_wrapper_getter_and_borrowed_mutations() {
    let baseline = audit_sources(&[("baseline.rs", BASELINE)]);
    assert!(baseline.is_empty(), "{baseline:#?}");
    for mutation in [
        format!("{BASELINE}\ntype Leak = PendingQualificationAdmission;"),
        format!(
            "{BASELINE}\nimpl Clone for VerifiedQualificationRunContext {{ fn clone(&self) -> Self {{ todo!() }} }}"
        ),
        format!("{BASELINE}\npub struct Wrapper {{ inner: PendingQualificationAdmission }}"),
        BASELINE.replace(
            "pub struct PendingQualificationAdmission",
            "#[derive(Debug)] pub struct PendingQualificationAdmission",
        ),
        BASELINE.replace(
            "impl PendingQualificationAdmission {",
            "impl PendingQualificationAdmission { pub fn bytes(&self) -> &[u8] { &self.inner }",
        ),
        BASELINE.replace("verify_and_consume(&mut self", "verify_and_consume(&self"),
        format!("{BASELINE}\npub use crate::VerifiedQualificationRunContext as ContextLeak;"),
        format!("{BASELINE}\npub use crate::QualificationRunContextVerifier as VerifierLeak;"),
        format!("{BASELINE}\npub use crate::PendingQualificationAdmission as AdmissionLeak;"),
        format!("{BASELINE}\npub use crate::context_model::*;"),
        format!("{BASELINE}\nmod nested {{ pub use crate::VerifiedQualificationRunContext; }}"),
    ] {
        assert!(
            !audit_sources(&[("mutation.rs", &mutation)]).is_empty(),
            "mutation escaped audit"
        );
    }
}

#[test]
fn surface_auditor_rejects_transitive_glob_and_public_module_aliases() {
    let mutations = [
        (
            "private alias followed by public glob",
            format!("{BASELINE}\nuse crate::context_model as cm; pub use cm::*;"),
        ),
        (
            "crate-visible alias followed by public glob",
            format!("{BASELINE}\npub(crate) use crate::context_model as cm; pub use cm::*;"),
        ),
        (
            "public renamed module re-export",
            format!("{BASELINE}\npub use crate::context_model as cm;"),
        ),
        (
            "nested public renamed module re-export",
            format!("{BASELINE}\npub mod exposed {{ pub use crate::context_model as renamed; }}"),
        ),
        (
            "public module containing alias-to-glob chain",
            format!(
                "{BASELINE}\npub mod exposed {{ use crate::context_model as cm; pub use cm::*; }}"
            ),
        ),
    ];
    let escaped = mutations
        .iter()
        .filter_map(|(label, mutation)| {
            audit_sources(&[("mutation.rs", mutation)])
                .is_empty()
                .then_some(*label)
        })
        .collect::<Vec<_>>();
    assert!(escaped.is_empty(), "mutations escaped audit: {escaped:?}");
}
