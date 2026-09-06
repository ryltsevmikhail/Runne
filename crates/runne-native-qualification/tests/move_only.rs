use runne_native_qualification::VerifiedQualificationFault;

// This is the authoritative spelling-independent invariant. Any internal
// implementation of one of these traits makes this test target fail to build.
static_assertions::assert_not_impl_any!(
    VerifiedQualificationFault:
        Clone,
        Copy,
        serde::Serialize,
        serde::Deserialize<'static>
);

#[test]
fn verified_qualification_fault_remains_move_only() {
    // Compilation of this test target is the assertion.
}
