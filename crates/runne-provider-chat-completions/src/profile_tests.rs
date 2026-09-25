use super::*;
use runne_provider::{ProviderTerminalPricing, ProviderUsage, TextProviderProfile};

fn profile() -> ChatCompletionsProfile {
    let profile = ChatCompletionsProfile::new(
        "test-provider",
        "gocode-chat-completions/test/1",
        "test-model",
        "2026-09-14",
        "https://provider.example",
        "/v1/chat/completions",
        [1; 32],
        [2; 32],
        4,
        100,
        400,
        100,
        1024,
        512,
    );
    ChatCompletionsProfile::new(
        "test-provider",
        "gocode-chat-completions/test/1",
        "test-model",
        "2026-09-14",
        "https://provider.example",
        "/v1/chat/completions",
        profile.recomputed_profile_digest(),
        profile.recomputed_pricing_revision_digest(),
        4,
        100,
        400,
        100,
        1024,
        512,
    )
}

#[test]
fn external_metering_preserves_usage_without_inventing_currency() {
    let profile = profile();
    let usage = ProviderUsage::new(10, 20, 0, 0).unwrap();
    assert_eq!(profile.currency(), "XXX");
    assert_eq!(profile.price_usage_micros(usage).unwrap(), 0);
    let priced = profile
        .price_terminal_usage(
            &profile.pricing_revision_digest(),
            &profile.profile_digest(),
            0,
            usage,
        )
        .unwrap();
    assert_eq!(priced.charge_micros(), 0);
    assert_eq!(priced.currency(), "XXX");
}

#[test]
fn profile_rejects_redirectable_or_non_https_endpoints() {
    let mut profile = profile();
    assert!(profile.validate().is_ok());
    profile = ChatCompletionsProfile::new(
        "test-provider",
        "gocode-chat-completions/test/1",
        "test-model",
        "2026-09-14",
        "http://provider.example",
        "/v1/chat/completions",
        [1; 32],
        [2; 32],
        4,
        100,
        400,
        100,
        1024,
        512,
    );
    assert!(profile.validate().is_err());
}
