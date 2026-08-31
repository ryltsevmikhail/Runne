#[path = "enrollment_transition_v2_v3_adversarial_tests.rs"]
mod adversarial;
#[path = "enrollment_transition_v2_v3_fixture.rs"]
mod fixture;
#[path = "enrollment_transition_v2_v3_original_tests.rs"]
mod original;

use fixture::Fixture;

#[test]
fn transition_rejects_v3_runtime_root_substitution() {
    let fixture = Fixture::new();
    assert!(fixture.transition(fixture.v3("/tmp/runtime")));
    assert!(!fixture.transition(fixture.v3("/tmp/other-runtime")));
}
