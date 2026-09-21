use jsonschema::{Draft, JSONSchema};
use runne_provider::{ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage};
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DEEPSEEK_REQUEST_MODEL,
    DEEPSEEK_RESPONSES_PROFILE_ID, DeepSeekProfileError, DeepSeekResponsesTextProfile,
    DeepSeekTransportPolicy,
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
    assert_eq!(
        source_digest,
        [
            0x01, 0x12, 0xc4, 0xb6, 0xce, 0x64, 0x73, 0x98, 0x10, 0xbb, 0x79, 0x80, 0x2e, 0xbb,
            0x5a, 0xe6, 0xfd, 0x8a, 0xc5, 0x63, 0xd1, 0xd1, 0x39, 0x7a, 0xc5, 0x1f, 0x07, 0xa1,
            0x90, 0x53, 0x81, 0x95,
        ]
    );
    assert_eq!(profile.profile_digest(), source_digest);
    assert_eq!(
        PROFILE_DIGEST.as_bytes(),
        b"sha256:0112c4b6ce64739810bb79802ebb5ae6fd8ac563d1d1397ac51f07a190538195"
    );
    assert_eq!(profile.profile_id(), "gocode-deepseek-responses-text/1");
    assert_eq!(profile.profile_id(), DEEPSEEK_RESPONSES_PROFILE_ID);
    assert_eq!(profile.provider_id(), "deepseek");
    assert_eq!(profile.origin(), "https://api.deepseek.com");
    assert_eq!(profile.path(), "/responses");
    assert_eq!(profile.request_model(), DEEPSEEK_REQUEST_MODEL);
    assert_eq!(DEEPSEEK_REQUEST_MODEL, "deepseek-flash");
    assert_eq!(profile.model_id(), DEEPSEEK_MODEL_ID);
    assert_eq!(DEEPSEEK_MODEL_ID, "deepseek-flash");
    assert_eq!(profile.model_revision(), DEEPSEEK_MODEL_REVISION);
    assert_eq!(DEEPSEEK_MODEL_REVISION, "2026-09-21");
    assert_eq!(
        DeepSeekTransportPolicy::for_profile(&profile)
            .expect("documented endpoint")
            .path(),
        "/responses"
    );
    assert_eq!(profile.currency(), "USD");
    assert_eq!(profile.max_input_entries(), 64);
    assert_eq!(profile.max_input_bytes(), 262_144);
    assert_eq!(profile.max_output_tokens(), 16_384);
    assert_eq!(profile.max_request_bytes(), 524_288);
    assert_eq!(PROFILE_DIGEST.len(), 71);
    assert_eq!(
        hex::encode(profile.pricing_revision_digest()),
        "9c626b1c22b5583abc2d9405340dd1c42e14b4c35937884836c6191eb03e8ece"
    );

    // Documented peak rates (cache-miss $0.3, cache-hit $0.006, output $1.2 per
    // 1M tokens) prorated with independent ceiling rounding per category.
    let usage = ProviderUsage::new(10, 2, 3, 0).unwrap();
    assert_eq!(profile.price_usage_micros(usage).unwrap(), 7);
    let full = ProviderUsage::new(1_000_000, 1_000_000, 0, 0).unwrap();
    assert_eq!(profile.price_usage_micros(full).unwrap(), 1_500_000);
    let cached = ProviderUsage::new(1_000_000, 1_000_000, 1_000_000, 0).unwrap();
    assert_eq!(profile.price_usage_micros(cached).unwrap(), 1_206_000);
    let priced = profile
        .price_terminal_usage(
            &profile.pricing_revision_digest(),
            &profile.profile_digest(),
            usage,
        )
        .unwrap();
    assert_eq!(priced.charge_micros(), 7);
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
        Box::new(|value| value["profile_id"] = json!("runne-deepseek-responses-text/1")),
        Box::new(|value| value["profile_revision"] = json!(1)),
        Box::new(|value| value["provider_id"] = json!("openai-compatible")),
        Box::new(|value| value["origin"] = json!("https://proxy.example")),
        Box::new(|value| value["path"] = json!("/v1/responses")),
        Box::new(|value| value["model"]["request_id"] = json!("deepseek-chat")),
        Box::new(|value| value["model"]["model_id"] = json!("deepseek-chat")),
        Box::new(|value| value["model"]["revision"] = json!("2026-08-16")),
        Box::new(|value| value["model"]["aliases"] = json!(["deepseek-v4-flash"])),
        Box::new(|value| value["pricing"]["revision"] = json!("deepseek-chat-base-2026-08-16/1")),
        Box::new(|value| value["pricing"]["input_micros"] = json!(270_000)),
        Box::new(|value| value["pricing"]["cached_input_micros"] = json!(28_000)),
        Box::new(|value| value["pricing"]["output_micros"] = json!(1_100_000)),
        Box::new(|value| value["pricing"]["long_context_enabled"] = json!(true)),
        Box::new(|value| value["capabilities"] = json!(["streaming", "tools"])),
        Box::new(|value| value["developer_prompt"] = json!("hidden")),
        Box::new(|value| {
            value["request"]["service_tier"] = json!("default");
        }),
        Box::new(|value| {
            value["request"]["background"] = json!(false);
        }),
        Box::new(|value| {
            value["request"]["store"] = json!(false);
        }),
        Box::new(|value| value["request"]["reasoning_effort"] = json!("low")),
        Box::new(|value| value["request"]["tools"] = json!([{"type": "web_search"}])),
        Box::new(|value| value["request"]["tool_choice"] = json!("auto")),
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
