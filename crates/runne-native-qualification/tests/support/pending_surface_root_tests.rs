use crate::pending_surface_audit::audit_sources;
use crate::pending_surface_fixture::BASELINE;

#[test]
fn reviewed_boundaries_must_be_crate_root_items() {
    let nested_lib = "mod hidden { mod pending; pub use pending::PendingQualificationFault; }";
    let nested_relay = r"
mod hidden {
    pub struct QualificationFaultRelayCodecV1;
    impl QualificationFaultRelayCodecV1 {
        pub fn decode(&self, frame: &[u8], expected: &QualificationFaultRelayBindingV1) -> Result<Option<PendingQualificationFault>, QualificationFaultRelayError> { todo!() }
    }
}
";
    let violations = audit_sources(&[
        ("pending.rs", BASELINE),
        ("lib.rs", nested_lib),
        ("relay.rs", nested_relay),
    ]);
    for required in [
        "private pending module declaration",
        "exact pending public re-export",
        "exact relay decode boundary",
    ] {
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(required)),
            "nested item was accepted as {required}: {violations:#?}"
        );
    }
}
