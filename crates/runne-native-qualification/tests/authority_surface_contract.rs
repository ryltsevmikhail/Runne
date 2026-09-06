#[path = "support/authority_surface_audit.rs"]
mod authority_surface_audit;
#[path = "support/authority_surface_expected.rs"]
mod authority_surface_expected;
#[path = "support/authority_surface_types.rs"]
mod authority_surface_types;
#[path = "support/authority_use_audit.rs"]
mod authority_use_audit;

use std::path::Path;

use authority_surface_audit::{audit_crate, audit_sources};

const BASELINE: &str = r"
/// Combined verifier.
pub struct QualificationAdmissionVerifier { context: QualificationRunContextVerifier }
impl QualificationAdmissionVerifier {
  pub fn from_compiled_policy() -> Self { todo!() }
  pub fn verify_exact_borrowed(&mut self, admission: &PendingQualificationAdmission, candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], now_unix_seconds: u64) -> Result<(), QualificationAdmissionVerificationError> { todo!() }
}
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
/// Pending context.
pub struct PendingQualificationRunContext { bytes: Vec<u8> }
/// Ordered output.
pub struct QualificationAdmissionRelayTranscript { bytes: Vec<u8> }
impl QualificationAdmissionRelayTranscript { pub fn into_bytes(self) -> Vec<u8> { self.bytes } }
/// Context codec.
pub struct QualificationRunContextRelayCodecV1 { inner: K }
impl QualificationRunContextRelayCodecV1 {
  pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self { todo!() }
  pub fn recognizes_frame(frame: &[u8]) -> bool { todo!() }
  pub fn decode(&self, frame: &[u8], expected: &QualificationRunContextRelayBindingV1) -> Result<PendingQualificationRunContext, QualificationRunContextRelayError> { todo!() }
}
/// Combined codec.
pub struct QualificationAdmissionRelayCodecV1 { inner: K }
impl QualificationAdmissionRelayCodecV1 {
  pub fn from_protected_activation(keys: &ProtectedActivationKeys) -> Self { todo!() }
  pub fn decode_transcript(&self, bytes: &[u8], context_binding: &QualificationRunContextRelayBindingV1, fault_binding: &QualificationFaultRelayBindingV1) -> Result<PendingQualificationAdmission, QualificationAdmissionRelayError> { todo!() }
}
";

#[test]
fn production_context_authorities_have_no_raw_or_reusable_escape_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = audit_crate(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn surface_auditor_rejects_every_combined_fence_facts_escape_shape() {
    let mutations = [
        "pub type Leak = VerifiedQualificationFenceFacts;",
        "pub struct Leak { value: VerifiedQualificationFenceFacts }",
        "pub trait Leak { fn take(value: VerifiedQualificationFenceFacts); }",
        "pub fn leak<T: Into<VerifiedQualificationFenceFacts>>(value: T) {}",
        "unsafe extern \"C\" { pub fn leak(value: VerifiedQualificationFenceFacts); }",
        "leak_fence_facts!(VerifiedQualificationFenceFacts);",
        "impl VerifiedQualificationFenceFacts { pub fn encode(self) -> Vec<u8> { vec![] } }",
        "pub fn perform_effect(value: VerifiedQualificationFenceFacts) {}",
        "pub use crate::VerifiedQualificationFenceFacts as FenceLeak;",
        "pub struct Leak<T = VerifiedQualificationFenceFacts> { value: T }",
    ];
    let escaped = mutations
        .iter()
        .filter(|mutation| audit_sources(&[("mutation.rs", mutation)]).is_empty())
        .count();
    assert_eq!(
        escaped, 0,
        "combined fence facts escape mutations must fail"
    );
}

#[test]
fn verifier_key_injection_is_visible_only_to_the_exact_test_support_cfg() {
    let signature = "pub fn test_only_from_verifying_keys(context_key: VerifyingKey, fault_key: VerifyingKey) -> Self { todo!() }";
    let unguarded = BASELINE.replace(
        "pub fn from_compiled_policy() -> Self { todo!() }",
        &format!("pub fn from_compiled_policy() -> Self {{ todo!() }} {signature}"),
    );
    assert!(!audit_sources(&[("unguarded.rs", &unguarded)]).is_empty());
    let guarded = BASELINE.replace(
        "pub fn from_compiled_policy() -> Self { todo!() }",
        &format!(
            "pub fn from_compiled_policy() -> Self {{ todo!() }} #[cfg(any(test, feature = \"test-support\"))] {signature}"
        ),
    );
    assert!(audit_sources(&[("guarded.rs", &guarded)]).is_empty());
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
        BASELINE.replace(
            "verify_exact_borrowed(&mut self",
            "verify_exact_borrowed(&self",
        ),
        BASELINE.replace(
            "admission: &PendingQualificationAdmission",
            "admission: PendingQualificationAdmission",
        ),
        format!("{BASELINE}\npub use crate::VerifiedQualificationRunContext as ContextLeak;"),
        format!("{BASELINE}\npub use crate::QualificationRunContextVerifier as VerifierLeak;"),
        format!("{BASELINE}\npub use crate::PendingQualificationAdmission as AdmissionLeak;"),
        format!("{BASELINE}\npub type ContextLeak = PendingQualificationRunContext;"),
        format!(
            "{BASELINE}\npub struct PairLeak {{ inner: QualificationAdmissionRelayTranscript }}"
        ),
        BASELINE.replace(
            "pub struct PendingQualificationRunContext",
            "#[derive(Clone)] pub struct PendingQualificationRunContext",
        ),
        BASELINE.replace(
            "pub struct QualificationAdmissionRelayTranscript",
            "#[derive(Debug)] pub struct QualificationAdmissionRelayTranscript",
        ),
        BASELINE.replace("pub fn into_bytes(self)", "pub fn into_bytes(&self)"),
        format!(
            "{BASELINE}\nimpl PendingQualificationRunContext {{ pub fn bytes(&self) -> &[u8] {{ &self.bytes }} }}"
        ),
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

#[test]
fn surface_auditor_recursively_rejects_every_context_relay_escape_shape() {
    let mutations = [
        format!("{BASELINE}\npub trait Leak {{ fn take(value: PendingQualificationRunContext); }}"),
        format!("{BASELINE}\npub trait Leak = Iterator<Item = PendingQualificationRunContext>;"),
        format!(
            "{BASELINE}\nunsafe extern \"C\" {{ pub fn leak(value: PendingQualificationRunContext); }}"
        ),
        format!(
            "{BASELINE}\nstruct Owner; impl Owner {{ pub fn leak(&self, value: Option<Box<PendingQualificationRunContext>>) {{}} }}"
        ),
        format!(
            "{BASELINE}\npub union Leak {{ value: std::mem::ManuallyDrop<PendingQualificationRunContext> }}"
        ),
        format!(
            "{BASELINE}\npub struct Leak {{ value: Option<Box<PendingQualificationRunContext>> }}"
        ),
        format!("{BASELINE}\npub const LEAK: Option<PendingQualificationRunContext> = None;"),
        format!("{BASELINE}\npub static LEAK: Option<PendingQualificationRunContext> = None;"),
        format!(
            "{BASELINE}\nimpl IntoIterator for QualificationAdmissionRelayTranscript {{ type Item = Vec<u8>; type IntoIter = std::vec::IntoIter<Vec<u8>>; fn into_iter(self) -> Self::IntoIter {{ todo!() }} }}"
        ),
        format!(
            "{BASELINE}\nimpl std::ops::Index<usize> for QualificationAdmissionRelayTranscript {{ type Output = [u8]; fn index(&self, _: usize) -> &Self::Output {{ todo!() }} }}"
        ),
        format!(
            "{BASELINE}\nimpl QualificationAdmissionRelayTranscript {{ pub fn first(&self) -> &[u8] {{ &self.bytes }} }}"
        ),
        format!(
            "{BASELINE}\nimpl QualificationAdmissionRelayTranscript {{ pub fn into_frames(self) -> [Vec<u8>; 2] {{ todo!() }} }}"
        ),
        format!("{BASELINE}\npub use crate::pending_context::*;"),
        format!(
            "{BASELINE}\npub mod exposed {{ pub use crate::PendingQualificationRunContext as Renamed; }}"
        ),
        format!("{BASELINE}\n#[path = \"outside.rs\"] mod substituted;"),
        BASELINE.replace(
            "pub struct PendingQualificationRunContext",
            "pub struct r#PendingQualificationRunContext",
        ),
    ];
    let escaped = mutations
        .iter()
        .filter(|mutation| audit_sources(&[("mutation.rs", mutation)]).is_empty())
        .count();
    assert_eq!(
        escaped, 0,
        "context relay escape mutations must all be rejected"
    );
}
