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

#[test]
fn transition_rejects_target_substitution_even_with_exact_broker_commitment() {
    use runne_api::{
        ActivationDispositionV1, ProtectedCredentialEnrollmentLaunchBindingV1,
        ProviderActivationBindingV1,
    };
    let fixture = Fixture::new();
    assert!(fixture.transition(fixture.v3("/tmp/runtime")));
    for constructor in [
        ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64,
        ProtectedCredentialEnrollmentLaunchBindingV1::linux_x86_64,
    ] {
        let binding = constructor(
            [6; 32],
            [7; 32],
            [8; 32],
            [9; 32],
            1,
            fixture.binding.broker_transfer_commitment().clone(),
        )
        .unwrap();
        let request = fixture::launch(
            "/tmp/runtime",
            [3; 32],
            fixture::id(1),
            fixture::id(2),
            ActivationDispositionV1::Existing(Box::new(
                fixture.owned.compatibility_owned_launch().stable().clone(),
            )),
        );
        assert!(!fixture.transition(fixture.v3_with(
            request,
            ProviderActivationBindingV1::openai_responses_text_v1(),
            binding,
        )));
    }
}
