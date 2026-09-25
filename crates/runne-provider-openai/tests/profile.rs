use jsonschema::{Draft, JSONSchema};
use runne_provider::{ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage};
use runne_provider_openai::{
    OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OPENAI_REQUEST_MODEL, OPENAI_RESPONSES_PROFILE_ID,
    OPENAI_SERVICE_TIER, OpenAiProfileError, OpenAiResponsesTextProfile,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROFILE_BYTES: &[u8] = include_bytes!("../../../docs/profiles/openai-responses-text-v1.json");
const PROFILE_DIGEST: &str = include_str!("../../../docs/profiles/openai-responses-text-v1.digest");
const PROFILE_SCHEMA: &str =
    include_str!("../../../docs/schemas/openai-responses-text-profile-v1.schema.json");
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
        OpenAiResponsesTextProfile::from_json(&bytes),
        Err(OpenAiProfileError::InvalidProfile)
    );
}

#[test]
fn exact_profile_schema_digest_identity_and_pricing_are_stable() {
    let value = parse_profile_value();
    assert!(schema().is_valid(&value));

    let profile = OpenAiResponsesTextProfile::from_json(PROFILE_BYTES).unwrap();
    let source_digest: [u8; 32] = Sha256::digest(PROFILE_BYTES).into();
    assert_eq!(
        source_digest,
        [
            0xd3, 0xe2, 0x09, 0x34, 0x77, 0x5d, 0x9d, 0x97, 0x03, 0x50, 0xd1, 0x6b, 0x78, 0xa1,
            0x73, 0x98, 0x85, 0xc0, 0x8d, 0xd5, 0xd3, 0xe4, 0x7b, 0x93, 0x07, 0x23, 0x3d, 0x4d,
            0xd0, 0xfb, 0xed, 0x80,
        ]
    );
    assert_eq!(profile.profile_digest(), source_digest);
    assert_eq!(
        PROFILE_DIGEST.trim(),
        "sha256:d3e20934775d9d970350d16b78a1739885c08dd5d3e47b9307233d4dd0fbed80"
    );
    assert_eq!(profile.profile_id(), "gocode-openai-responses-text/1");
    assert_eq!(profile.profile_id(), OPENAI_RESPONSES_PROFILE_ID);
    assert_eq!(profile.provider_id(), "openai");
    assert_eq!(profile.origin(), "https://api.openai.com");
    assert_eq!(profile.path(), "/v1/responses");
    assert_eq!(profile.request_model(), OPENAI_REQUEST_MODEL);
    assert_eq!(profile.service_tier(), OPENAI_SERVICE_TIER);
    assert_eq!(profile.model_id(), OPENAI_MODEL_ID);
    assert_eq!(profile.model_revision(), OPENAI_MODEL_REVISION);
    assert_eq!(profile.currency(), "USD");
    assert_eq!(profile.max_input_entries(), 64);
    assert_eq!(profile.max_input_bytes(), 262_144);
    assert_eq!(profile.max_output_tokens(), 16_384);
    assert_eq!(profile.max_request_bytes(), 524_288);
    assert_eq!(
        hex::encode(profile.pricing_revision_digest()),
        "bef5b081d3878eda65e5f0bdcd919f1b18aba7b5b166deeebf7c812f06582072"
    );

    let usage = ProviderUsage::new(10, 2, 3, 0).unwrap();
    assert_eq!(profile.price_usage_micros(usage).unwrap(), 97);
    let priced = profile
        .price_terminal_usage(
            &profile.pricing_revision_digest(),
            &profile.profile_digest(),
            1_788_501_600,
            usage,
        )
        .unwrap();
    assert_eq!(priced.charge_micros(), 97);
    assert_eq!(priced.currency(), "USD");
    assert_eq!(
        profile.price_terminal_usage(&[3; 32], &profile.profile_digest(), 1_788_501_600, usage),
        Err(ProviderTerminalPricingError::Unavailable)
    );
    assert_eq!(
        profile.price_terminal_usage(
            &profile.pricing_revision_digest(),
            &[4; 32],
            1_788_501_600,
            usage,
        ),
        Err(ProviderTerminalPricingError::Unavailable)
    );
    assert_eq!(
        profile.price_usage_micros(ProviderUsage::new(272_001, 1, 0, 0).unwrap()),
        Err(OpenAiProfileError::UnsupportedPricingTier)
    );
}

#[test]
fn aliases_endpoint_model_pricing_and_request_policy_are_exact() {
    let original = parse_profile_value();
    let mutations: Vec<ProfileMutation> = vec![
        Box::new(|value| value["profile_id"] = json!("runne-openai-responses-text/1")),
        Box::new(|value| value["profile_revision"] = json!(1)),
        Box::new(|value| value["provider_id"] = json!("openai-compatible")),
        Box::new(|value| value["origin"] = json!("https://proxy.example")),
        Box::new(|value| value["path"] = json!("/v1/chat/completions")),
        Box::new(|value| value["model"]["request_id"] = json!("gpt-5.5")),
        Box::new(|value| value["model"]["model_id"] = json!("gpt-5.5-latest")),
        Box::new(|value| value["model"]["revision"] = json!("latest")),
        Box::new(|value| value["model"]["aliases"] = json!(["gpt-5.5"])),
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
        OpenAiResponsesTextProfile::from_json(&semantically_equal_but_noncanonical),
        Err(OpenAiProfileError::InvalidProfile)
    );
}
