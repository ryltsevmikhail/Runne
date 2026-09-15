use super::*;

fn payg() -> ChatCompletionsAccounting {
    ChatCompletionsAccounting::Payg {
        input_micros_per_million: 1_000,
        output_micros_per_million: 2_000,
        cached_input_micros_per_million: 0,
    }
}

fn limits() -> ConfiguredChatModelLimits {
    ConfiguredChatModelLimits::new(
        131_072, 100_000, 16_384, 16_384, 1_024, 64, 65_536, 65_536, 524_288, 65_536,
    )
}

#[test]
fn configured_builder_returns_a_valid_usable_profile() {
    let configured =
        cloudflare_workers_with_limits("account-1", "@cf/model-v1", payg(), limits()).unwrap();
    assert_eq!(configured.origin(), "https://api.cloudflare.com");
    assert_eq!(
        configured.thinking_mode(),
        ChatCompletionsThinkingMode::None
    );
    assert_eq!(configured.profile().max_input_bytes(), 65_536);
    assert_eq!(
        configured
            .profile()
            .model_limits()
            .unwrap()
            .context_tokens(),
        131_072
    );
    assert_eq!(
        configured.profile().billing_mode(),
        Some(ChatCompletionsBillingMode::ExternalPayg)
    );
    configured.profile().validate().unwrap();
    ChatCompletionsRenderer::new(configured.into_profile()).unwrap();
}

#[test]
fn legacy_builders_and_invalid_limits_fail_closed() {
    assert_eq!(
        bedrock("us-east-1", "model", payg()),
        Err(ConfiguredChatProfileError::MissingLimits)
    );
    assert_eq!(
        bedrock_with_limits("us-east-1/evil", "model", payg(), limits()),
        Err(ConfiguredChatProfileError::InvalidComponent)
    );
    let overflow = ConfiguredChatModelLimits::new(
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        1,
        1,
        1,
        1,
        1,
    );
    assert_eq!(
        nvidia_with_limits("model", payg(), overflow),
        Err(ConfiguredChatProfileError::InvalidLimits)
    );
}

#[test]
fn configured_input_bound_cannot_exceed_conservative_token_capacity() {
    let invalid = ConfiguredChatModelLimits::new(
        3_000, 1_000, 1_000, 1_000, 1_000, 4, 2_000, 1_001, 4_096, 2_048,
    );
    assert_eq!(
        nvidia_with_limits("model", payg(), invalid),
        Err(ConfiguredChatProfileError::InvalidLimits)
    );
}

#[test]
fn manually_owned_profile_cannot_bypass_input_token_capacity_validation() {
    let profile = ChatCompletionsProfile::new_owned_with_accounting(
        "nvidia".into(),
        "configured/1".into(),
        "model".into(),
        "revision".into(),
        "https://provider.example".into(),
        "/v1/chat/completions".into(),
        [0; 32],
        [0; 32],
        4,
        2_000,
        1_001,
        1_000,
        4_096,
        2_048,
        ChatCompletionsModelLimits::new(3_000, 1_000, 1_000, 1_000),
        ChatCompletionsBillingMode::ExternalPayg,
        payg(),
        ChatCompletionsThinkingMode::None,
    )
    .with_recomputed_digests();
    assert_eq!(
        profile.validate(),
        Err(ChatCompletionsProfileError::Invalid)
    );
    assert!(ChatCompletionsRenderer::new(profile).is_err());
}

#[test]
fn configured_cloud_billing_rejects_subscriptions_and_bad_rates() {
    assert_eq!(
        cloudflare_gateway_with_limits(
            "account",
            "gateway",
            "model",
            ChatCompletionsAccounting::SubscriptionQuotaExternallyMetered,
            ChatCompletionsBillingMode::UnifiedBilling,
            limits(),
        ),
        Err(ConfiguredChatProfileError::UnsupportedBilling)
    );
    assert_eq!(
        cloudflare_gateway_with_limits(
            "account",
            "gateway",
            "model",
            payg(),
            ChatCompletionsBillingMode::ExternalPayg,
            limits(),
        ),
        Err(ConfiguredChatProfileError::InvalidBillingMode)
    );
    assert_eq!(
        cloudflare_gateway_with_limits(
            "account",
            "gateway",
            "model",
            ChatCompletionsAccounting::Payg {
                input_micros_per_million: 1,
                output_micros_per_million: 1,
                cached_input_micros_per_million: 2,
            },
            ChatCompletionsBillingMode::StoredByok,
            limits(),
        ),
        Err(ConfiguredChatProfileError::UnsupportedBilling)
    );
    assert_eq!(
        nvidia_with_limits(
            "model",
            ChatCompletionsAccounting::ExternallyBilledUnpriced,
            limits()
        ),
        Err(ConfiguredChatProfileError::Unpriced)
    );
    assert_eq!(
        nvidia_with_limits(
            "model",
            ChatCompletionsAccounting::Payg {
                input_micros_per_million: 0,
                output_micros_per_million: 1,
                cached_input_micros_per_million: 0,
            },
            limits(),
        ),
        Err(ConfiguredChatProfileError::UnsupportedBilling)
    );
}

#[test]
fn gateway_billing_mode_is_hash_bound() {
    let unified = cloudflare_gateway_with_limits(
        "account",
        "gateway",
        "model",
        payg(),
        ChatCompletionsBillingMode::UnifiedBilling,
        limits(),
    )
    .unwrap();
    let stored = cloudflare_gateway_with_limits(
        "account",
        "gateway",
        "model",
        payg(),
        ChatCompletionsBillingMode::StoredByok,
        limits(),
    )
    .unwrap();
    assert_ne!(unified.profile_digest(), stored.profile_digest());
    assert_eq!(
        unified.profile().billing_mode(),
        Some(ChatCompletionsBillingMode::UnifiedBilling)
    );
    assert_eq!(
        stored.profile().billing_mode(),
        Some(ChatCompletionsBillingMode::StoredByok)
    );
}
