use runne_api::{
    ActivationDispositionV1, ExecutableIdentityV1, ProtectedLaunchRequestV2,
    ProtectedRuntimeProfileV1, ProviderActivationBindingV1,
};

use super::fixture::{Fixture, id, launch_with};

fn rejects_original(
    fixture: &Fixture,
    authority: [u8; 16],
    host: [u8; 16],
    profile: ProtectedRuntimeProfileV1,
    executable: ExecutableIdentityV1,
    provider: ProviderActivationBindingV1,
) -> bool {
    let original = ProtectedLaunchRequestV2::new(
        launch_with(
            "/tmp/runtime",
            [3; 32],
            authority,
            host,
            ActivationDispositionV1::FirstActivation,
            profile.clone(),
            executable.clone(),
        ),
        provider.clone(),
    )
    .unwrap();
    let request = fixture.v3_with(
        launch_with(
            "/tmp/runtime",
            [3; 32],
            authority,
            host,
            ActivationDispositionV1::Existing(Box::new(
                fixture.owned.compatibility_owned_launch().stable().clone(),
            )),
            profile,
            executable,
        ),
        provider,
        fixture.binding.clone(),
    );
    let mut input = fixture.input();
    input.original = &original;
    fixture.admits(request, input, |_, _| true, &fixture.channel)
}

#[test]
fn transition_rejects_original_v2_coherence_substitutions() {
    let fixture = Fixture::new();
    let base = || {
        ProtectedRuntimeProfileV1::new(
            runne_api::PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
            1,
            "fixture",
            [1; 32],
            [2; 32],
        )
        .unwrap()
    };
    assert!(!rejects_original(
        &fixture,
        id(1),
        id(2),
        ProtectedRuntimeProfileV1::new(
            runne_api::PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
            1,
            "fixture",
            [31; 32],
            [2; 32],
        )
        .unwrap(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
    ));
    assert!(!rejects_original(
        &fixture,
        id(1),
        id(2),
        base(),
        ExecutableIdentityV1::new([31; 32], [5; 32], 1).unwrap(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
    ));
    assert!(!rejects_original(
        &fixture,
        id(1),
        id(2),
        base(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        ProviderActivationBindingV1::deepseek_responses_text_v1(),
    ));
    assert!(!rejects_original(
        &fixture,
        id(31),
        id(32),
        base(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
    ));
}
