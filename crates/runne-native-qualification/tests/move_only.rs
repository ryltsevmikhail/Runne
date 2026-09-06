use runne_native_qualification::{
    PendingQualificationAdmission, PendingQualificationFault, QualificationFaultRelayCodecV1,
    QualificationRunContextVerifier, VerifiedQualificationFault, VerifiedQualificationRunContext,
};

// This is the authoritative spelling-independent invariant. Any internal
// implementation of one of these traits makes this test target fail to build.
static_assertions::assert_not_impl_any!(
    VerifiedQualificationFault:
        Clone,
        Copy,
        serde::Serialize,
        serde::Deserialize<'static>
);
static_assertions::assert_not_impl_any!(
    VerifiedQualificationRunContext:
        Clone,
        Copy,
        std::fmt::Debug,
        serde::Serialize,
        serde::Deserialize<'static>
);
static_assertions::assert_not_impl_any!(
    PendingQualificationAdmission:
        Clone,
        Copy,
        std::fmt::Debug,
        serde::Serialize,
        serde::Deserialize<'static>
);
static_assertions::assert_not_impl_any!(
    QualificationRunContextVerifier:
        Clone,
        Copy,
        serde::Serialize,
        serde::Deserialize<'static>
);
static_assertions::assert_not_impl_any!(
    PendingQualificationFault:
        Clone,
        Copy,
        std::fmt::Debug,
        serde::Serialize,
        serde::Deserialize<'static>
);
static_assertions::assert_not_impl_any!(
    QualificationFaultRelayCodecV1:
        Clone,
        Copy,
        serde::Serialize,
        serde::Deserialize<'static>
);

#[test]
fn verified_qualification_fault_remains_move_only() {
    // Compilation of this test target is the assertion.
}
