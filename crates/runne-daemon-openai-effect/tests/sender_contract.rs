use runne_daemon_openai_effect::{OpenAiEffect, effect_from_loopback_fixture};

fn accepts_only_sealed_effect(_: &dyn OpenAiEffect) {}

#[test]
fn explicit_client_constructor_returns_only_the_sealed_effect_object() {
    let client = reqwest::Client::builder().https_only(true).build().unwrap();
    let (effect, _) = effect_from_loopback_fixture(client).unwrap();
    accepts_only_sealed_effect(effect.as_ref());
}
