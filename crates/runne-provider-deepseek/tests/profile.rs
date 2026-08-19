use jsonschema::{Draft, JSONSchema};
use runne_provider::{ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage};
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DEEPSEEK_REQUEST_MODEL,
    DEEPSEEK_RESPONSES_PROFILE_ID, DEEPSEEK_SERVICE_TIER, DeepSeekProfileError,
    DeepSeekResponsesTextProfile,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROFILE_BYTES: &[u8] =
    include_bytes!("../../../docs/profiles/deepseek-responses-text-v1.json");
const PROFILE_DIGEST: &str =
    include_str!("../../../docs/profiles/deepseek-responses-text-v1.digest");
const PROFILE_SCHEMA: &str =
    include_str!("../../../docs/schemas/deepseek-responses-text-profile-v1.schema.json");
type ProfileMutation = Box<dyn Fn(&mut Value)>;

fn schema() -> JSONSchema {
    let value: Value = serde_json::from_str(PROFILE_SCHEMA).expect("schema JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("profile schema")
}

fn parse_profile_value() -> Value {
    serde_json::from_slice(PROFILE_BYTES).expect("profile JSON")
}

fn assert_rejected(mut value: Value, mutate: impl FnOnce(&mut Value)) {
    mutate(&mut value);
    assert!(!schema().is_valid(&value), "schema accepted {value}");
    let bytes = serde_json::to_vec(&value).expect("mutated profile bytes");
    assert_eq!(
        DeepSeekResponsesTextProfile::from_json(&bytes),
        Err(DeepSeekProfileError::InvalidProfile)
    );
}

#[test]
fn exact_profile_schema_digest_identity_and_pricing_are_stable() {
    let value = parse_profile_value();
    assert!(schema().is_valid(&value));

    let profile = DeepSeekResponsesTextProfile::from_json(PROFILE_BYTES).unwrap();
    let source_digest: [u8; 32] = Sha256::digest(PROFILE_BYTES).into();
    assert_eq!(profile.profile_digest(), source_digest);
    assert_eq!(
        PROFILE_DIGEST.trim(),
        format!("sha256:{}", hex::encode(source_digest))
    );
    assert_eq!(profile.profile_id(), DEEPSEEK_RESPONSES_PROFILE_ID);
    assert_eq!(profile.provider_id(), "deepseek");
    assert_eq!(profile.origin(), "https://api.deepseek.com");
    assert_eq!(profile.path(), "/v1/responses");
    assert_eq!(profile.request_model(), DEEPSEEK_REQUEST_MODEL);
    assert_eq!(profile.service_tier(), DEEPSEEK_SERVICE_TIER);
    assert_eq!(profile.model_id(), DEEPSEEK_MODEL_ID);
    assert_eq!(profile.model_revision(), DEEPSEEK_MODEL_REVISION);
    assert_eq!(profile.currency(), "USD");
    assert_eq!(profile.max_input_entries(), 64);
    assert_eq!(profile.max_input_bytes(), 262_144);
    assert_eq!(profile.max_output_tokens(), 16_384);
    assert_eq!(profile.max_request_bytes(), 524_288);
    assert_ne!(profile.pricing_revision_digest(), [0; 32]);

    let usage = ProviderUsage::new(10, 2, 3, 0).unwrap();
    assert_eq!(profile.price_usage_micros(usage).unwrap(), 6);
    let priced = profile
        .price_terminal_usage(
            &profile.pricing_revision_digest(),
            &profile.profile_digest(),
            usage,
        )
        .unwrap();
    assert_eq!(priced.charge_micros(), 6);
    assert_eq!(priced.currency(), "USD");
    assert_eq!(
        profile.price_terminal_usage(&[3; 32], &profile.profile_digest(), usage),
        Err(ProviderTerminalPricingError::Unavailable)
    );
    assert_eq!(
        profile.price_terminal_usage(&profile.pricing_revision_digest(), &[4; 32], usage),
        Err(ProviderTerminalPricingError::Unavailable)
    );
    assert_eq!(
        profile.price_usage_micros(ProviderUsage::new(1_000_001, 1, 0, 0).unwrap()),
        Err(DeepSeekProfileError::UnsupportedPricingTier)
    );
}

#[test]
fn aliases_endpoint_model_pricing_and_request_policy_are_exact() {
    let original = parse_profile_value();
    let mutations: Vec<ProfileMutation> = vec![
        Box::new(|value| value["profile_id"] = json!("runne-deepseek-responses-text")),
        Box::new(|value| value["profile_revision"] = json!(2)),
        Box::new(|value| value["provider_id"] = json!("openai-compatible")),
        Box::new(|value| value["origin"] = json!("https://proxy.example")),
        Box::new(|value| value["path"] = json!("/v1/chat/completions")),
        Box::new(|value| value["model"]["request_id"] = json!("deepseek-chat-v4")),
        Box::new(|value| value["model"]["model_id"] = json!("deepseek-chat-latest")),
        Box::new(|value| value["model"]["revision"] = json!("latest")),
        Box::new(|value| value["model"]["aliases"] = json!(["deepseek-chat"])),
        Box::new(|value| value["pricing"]["revision"] = json!("latest")),
        Box::new(|value| value["pricing"]["input_micros"] = json!(4_999_999)),
        Box::new(|value| value["pricing"]["cached_input_micros"] = json!(499_999)),
        Box::new(|value| value["pricing"]["output_micros"] = json!(29_999_999)),
        Box::new(|value| value["pricing"]["long_context_enabled"] = json!(true)),
        Box::new(|value| value["capabilities"] = json!(["streaming", "tools"])),
        Box::new(|value| value["developer_prompt"] = json!("hidden")),
        Box::new(|value| value["request"]["service_tier"] = json!("auto")),
        Box::new(|value| {
            value["request"]
                .as_object_mut()
                .expect("request object")
                .remove("service_tier");
        }),
        Box::new(|value| value["request"]["reasoning_effort"] = json!("low")),
        Box::new(|value| value["request"]["tools"] = json!([{"type": "web_search"}])),
        Box::new(|value| value["request"]["tool_choice"] = json!("auto")),
        Box::new(|value| value["request"]["background"] = json!(true)),
        Box::new(|value| value["request"]["store"] = json!(true)),
        Box::new(|value| value["request"]["stream"] = json!(false)),
        Box::new(|value| value["limits"]["max_input_entries"] = json!(65)),
        Box::new(|value| value["limits"]["max_input_bytes"] = json!(262_145)),
        Box::new(|value| value["limits"]["max_output_tokens"] = json!(128_000)),
        Box::new(|value| value["unexpected"] = json!(true)),
    ];

    for mutate in mutations {
        assert_rejected(original.clone(), mutate);
    }

    let semantically_equal_but_noncanonical =
        serde_json::to_vec_pretty(&original).expect("pretty profile bytes");
    assert_eq!(
        DeepSeekResponsesTextProfile::from_json(&semantically_equal_but_noncanonical),
        Err(DeepSeekProfileError::InvalidProfile)
    );
}
