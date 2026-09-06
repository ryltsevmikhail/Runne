use crate::pending_surface_audit::audit_sources;

pub const BASELINE: &str = r"
pub struct PendingQualificationFault { bytes: Vec<u8> }
impl PendingQualificationFault {
    pub fn from_admitted_frame(bytes: Vec<u8>) -> Result<Self, QualificationFaultError> { todo!() }
    pub fn verify_and_consume(self, verifier: &mut crate::QualificationFaultVerifier, context: &QualificationFaultContext, now_unix_seconds: u64) -> Result<VerifiedQualificationFault, QualificationFaultError> { todo!() }
    pub fn encode_relay(self, codec: &crate::QualificationFaultRelayCodecV1, binding: &runne_api::QualificationFaultRelayBindingV1) -> Result<Vec<u8>, crate::QualificationFaultRelayError> { todo!() }
}
";

const LIB_SURFACE: &str = r"
mod pending;
pub use pending::PendingQualificationFault;
";

const RELAY_SURFACE: &str = r"
pub struct QualificationFaultRelayCodecV1;
impl QualificationFaultRelayCodecV1 {
    pub fn decode(&self, frame: &[u8], expected: &QualificationFaultRelayBindingV1) -> Result<Option<PendingQualificationFault>, QualificationFaultRelayError> { todo!() }
}
";

pub fn audit_fixture(pending: &str, extra: &[(&str, &str)]) -> Vec<String> {
    let mut sources = vec![
        ("pending.rs", pending),
        ("lib.rs", LIB_SURFACE),
        ("relay.rs", RELAY_SURFACE),
    ];
    sources.extend_from_slice(extra);
    audit_sources(&sources)
}

pub fn appended(mutation: &str) -> String {
    format!("{BASELINE}\n{mutation}\n")
}

pub fn reject_all(cases: &[(&str, String)]) {
    let escaped = cases
        .iter()
        .filter_map(|(label, source)| audit_fixture(source, &[]).is_empty().then_some(*label))
        .collect::<Vec<_>>();
    assert!(escaped.is_empty(), "mutations escaped: {escaped:?}");
}

pub fn reject_public_all(cases: &[(&str, String)]) {
    let escaped = cases
        .iter()
        .filter_map(|(label, source)| {
            audit_fixture(BASELINE, &[("leak.rs", source)])
                .is_empty()
                .then_some(*label)
        })
        .collect::<Vec<_>>();
    assert!(escaped.is_empty(), "mutations escaped: {escaped:?}");
}

pub fn require_violations(label: &str, source: &str, expected: &[&str]) {
    let violations = audit_fixture(source, &[]);
    for fragment in expected {
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(fragment)),
            "{label} lacked {fragment:?}: {violations:#?}"
        );
    }
}
