use std::os::fd::AsRawFd as _;

use runne_api::{
    ActivationDispositionV1, ProtectedOwnedLaunchV2, ProviderActivationBindingV1,
    StableRuntimeBindingV1,
};

use super::fixture::{Fixture, id, launch};

#[test]
fn transition_rejects_v2_native_and_prelude_substitutions() {
    let fixture = Fixture::new();
    let request = fixture.v3("/tmp/runtime");
    let wrong_keys = launch(
        "/tmp/runtime",
        [31; 32],
        id(1),
        id(2),
        ActivationDispositionV1::FirstActivation,
    )
    .derive_keys();
    let wrong_owned = ProtectedOwnedLaunchV2::new(
        fixture.owned.compatibility_owned_launch().clone(),
        ProviderActivationBindingV1::deepseek_responses_text_v1(),
    )
    .unwrap();
    let mut input = fixture.input();
    input.keys = &wrong_keys;
    assert!(!fixture.admits(request.clone(), input, |_, _| true, &fixture.channel));
    let mut input = fixture.input();
    input.owned = &wrong_owned;
    assert!(!fixture.admits(request.clone(), input, |_, _| true, &fixture.channel));
    let mut input = fixture.input();
    input.last_sequence = 1;
    assert!(!fixture.admits(request.clone(), input, |_, _| true, &fixture.channel));
    let mut input = fixture.input();
    input.now = 21;
    assert!(!fixture.admits(request, input, |_, _| true, &fixture.channel));
    assert!(!fixture.admits(
        fixture.v3("/tmp/runtime"),
        fixture.input(),
        |_, _| false,
        &fixture.channel
    ));
}

#[test]
fn transition_rejects_v3_binding_and_launch_substitutions() {
    let fixture = Fixture::new();
    for binding in [
        fixture.binding([26; 32], [7; 32], [8; 32], [9; 32], 1),
        fixture.binding([6; 32], [27; 32], [8; 32], [9; 32], 1),
        fixture.binding([6; 32], [7; 32], [28; 32], [9; 32], 1),
        fixture.binding([6; 32], [7; 32], [8; 32], [29; 32], 1),
        fixture.binding([6; 32], [7; 32], [8; 32], [9; 32], 2),
    ] {
        assert!(!fixture.transition(fixture.v3_with(
            launch(
                "/tmp/runtime",
                [3; 32],
                id(1),
                id(2),
                ActivationDispositionV1::Existing(Box::new(
                    fixture.owned.compatibility_owned_launch().stable().clone()
                ))
            ),
            ProviderActivationBindingV1::openai_responses_text_v1(),
            binding,
        )));
    }
    assert!(!fixture.transition(fixture.v3_with(
        launch(
            "/tmp/runtime",
            [3; 32],
            id(1),
            id(2),
            ActivationDispositionV1::Existing(Box::new(
                fixture.owned.compatibility_owned_launch().stable().clone()
            ))
        ),
        ProviderActivationBindingV1::deepseek_responses_text_v1(),
        fixture.binding.clone(),
    )));
    assert!(!fixture.transition(fixture.v3_with(
        launch(
            "/tmp/runtime",
            [31; 32],
            id(1),
            id(2),
            ActivationDispositionV1::Existing(Box::new(
                fixture.owned.compatibility_owned_launch().stable().clone()
            ))
        ),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        fixture.binding.clone(),
    )));
    assert!(!fixture.transition(fixture.v3_with(
        launch(
            "/tmp/runtime",
            [3; 32],
            id(31),
            id(2),
            ActivationDispositionV1::Existing(Box::new(
                fixture.owned.compatibility_owned_launch().stable().clone()
            ))
        ),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        fixture.binding.clone(),
    )));
}

#[test]
fn transition_rejects_disposition_claim_and_socket_substitution() {
    let fixture = Fixture::new();
    assert!(!fixture.transition(fixture.v3_with(
        launch(
            "/tmp/runtime",
            [3; 32],
            id(1),
            id(2),
            ActivationDispositionV1::FirstActivation
        ),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        fixture.binding.clone(),
    )));
    let wrong_stable =
        StableRuntimeBindingV1::new(id(30), "local-owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap();
    assert!(!fixture.transition(fixture.v3_with(
        launch(
            "/tmp/runtime",
            [3; 32],
            id(1),
            id(2),
            ActivationDispositionV1::Existing(Box::new(wrong_stable))
        ),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        fixture.binding.clone(),
    )));
    assert!(!fixture.admits(
        fixture.v3("/tmp/runtime"),
        fixture.input(),
        |_, claims| *claims.release_tuple_digest() == [42; 32],
        &fixture.channel
    ));
    let other = Fixture::new();
    let expected = fixture.channel.unix_stream().as_raw_fd();
    assert!(!fixture.admits(
        fixture.v3("/tmp/runtime"),
        fixture.input(),
        |stream, _| stream.as_raw_fd() == expected,
        &other.channel
    ));
}
