use super::ProviderCredentialProviderV2;

const CATALOG_IDS: [&str; 40] = [
    "anthropic",
    "ant-ling",
    "azure-openai-responses",
    "openai",
    "deepseek",
    "nvidia",
    "google",
    "amazon-bedrock",
    "mistral",
    "groq",
    "cerebras",
    "cloudflare-ai-gateway",
    "cloudflare-workers-ai",
    "xai",
    "openrouter",
    "vercel-ai-gateway",
    "zai",
    "zai-coding-cn",
    "openai-codex",
    "github-copilot",
    "google-vertex",
    "opencode",
    "opencode-go",
    "radius",
    "huggingface",
    "fireworks",
    "together",
    "baseten",
    "kimi-coding",
    "minimax",
    "minimax-cn",
    "moonshotai",
    "moonshotai-cn",
    "qwen-token-plan",
    "qwen-token-plan-individual",
    "qwen-token-plan-cn",
    "xiaomi",
    "xiaomi-token-plan-cn",
    "xiaomi-token-plan-ams",
    "xiaomi-token-plan-sgp",
];

#[test]
fn all_catalog_credentials_round_trip_and_unknown_is_rejected() {
    for id in CATALOG_IDS {
        let value: ProviderCredentialProviderV2 =
            serde_json::from_str(&format!("\"{id}\"")).unwrap();
        assert_eq!(value.as_str(), id);
    }
    assert!(serde_json::from_str::<ProviderCredentialProviderV2>("\"unknown-provider\"").is_err());
}

#[test]
fn protected_tags_are_unique_and_preserve_legacy_wire_values() {
    let mut tags: Vec<u8> = CATALOG_IDS
        .iter()
        .map(|id| ProviderCredentialProviderV2::parse(id).unwrap().wire_tag())
        .collect();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), CATALOG_IDS.len());
    assert_eq!(ProviderCredentialProviderV2::OpenAi.wire_tag(), 1);
    assert_eq!(ProviderCredentialProviderV2::DeepSeek.wire_tag(), 2);
    assert_eq!(ProviderCredentialProviderV2::Zai.wire_tag(), 3);
    assert_eq!(
        ProviderCredentialProviderV2::QwenTokenPlanIndividual.wire_tag(),
        4
    );
}
