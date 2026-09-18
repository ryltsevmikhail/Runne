//! Lookup and renderer-safe projection for the provider catalog.

use super::{catalog_data::CATALOG_ENTRIES, types::*};

/// Returns a catalog entry by exact provider ID.
pub fn provider_catalog_entry(provider_id: &str) -> Option<ProviderCatalogEntryV1> {
    CATALOG_ENTRIES
        .iter()
        .copied()
        .find(|entry| entry.provider_id == provider_id)
}

/// Returns all stable text provider catalog entries.
pub const fn provider_catalog() -> &'static [ProviderCatalogEntryV1] {
    CATALOG_ENTRIES
}

/// Returns a renderer-safe projection of the authoritative backend catalog.
pub fn provider_catalog_snapshot() -> Vec<ProviderCatalogSnapshotV1> {
    CATALOG_ENTRIES
        .iter()
        .copied()
        .map(|entry| ProviderCatalogSnapshotV1 {
            provider_id: entry.provider_id.to_owned(),
            display_name: provider_display_name(entry.provider_id).to_owned(),
            protocol: entry.protocol,
            auth_options: entry.auth_options.to_vec(),
            quota: entry.quota,
            implementation: entry.implementation,
        })
        .collect()
}

fn provider_display_name(provider_id: &str) -> &'static str {
    match provider_id {
        "amazon-bedrock" => "Amazon Bedrock",
        "ant-ling" => "Ant Ling",
        "anthropic" => "Anthropic",
        "azure-openai-responses" => "Azure OpenAI",
        "baseten" => "Baseten",
        "cerebras" => "Cerebras",
        "cloudflare-ai-gateway" => "Cloudflare AI Gateway",
        "cloudflare-workers-ai" => "Cloudflare Workers AI",
        "deepseek" => "DeepSeek",
        "fireworks" => "Fireworks",
        "github-copilot" => "GitHub Copilot",
        "google" => "Google",
        "google-vertex" => "Google Vertex AI",
        "groq" => "Groq",
        "huggingface" => "Hugging Face",
        "kimi-coding" => "Kimi For Coding",
        "minimax" => "MiniMax",
        "minimax-cn" => "MiniMax CN",
        "mistral" => "Mistral",
        "moonshotai" => "Moonshot AI",
        "moonshotai-cn" => "Moonshot AI CN",
        "nvidia" => "NVIDIA",
        "openai" => "OpenAI",
        "openai-codex" => "OpenAI Codex",
        "opencode" => "OpenCode Zen",
        "opencode-go" => "OpenCode Go",
        "openrouter" => "OpenRouter",
        "qwen-token-plan" => "Qwen Token Plan",
        "qwen-token-plan-cn" => "Qwen Token Plan CN",
        "qwen-token-plan-individual" => "Qwen Token Plan Individual",
        "radius" => "Radius",
        "together" => "Together",
        "vercel-ai-gateway" => "Vercel AI Gateway",
        "xai" => "xAI",
        "xiaomi" => "Xiaomi",
        "xiaomi-token-plan-ams" => "Xiaomi Token Plan AMS",
        "xiaomi-token-plan-cn" => "Xiaomi Token Plan CN",
        "xiaomi-token-plan-sgp" => "Xiaomi Token Plan SGP",
        "zai" => "Z.AI",
        "zai-coding-cn" => "Z.AI Coding CN",
        _ => "Unknown provider",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_contains_exact_text_provider_ids_without_duplicates() {
        assert_eq!(CATALOG_ENTRIES.len(), 40);
        for (index, entry) in CATALOG_ENTRIES.iter().enumerate() {
            assert!(!entry.provider_id.is_empty());
            assert!(
                CATALOG_ENTRIES[..index]
                    .iter()
                    .all(|previous| previous.provider_id != entry.provider_id)
            );
        }
        assert!(provider_catalog_entry("openrouter-images").is_none());
    }

    #[test]
    fn subscription_metadata_keeps_billing_separate_from_runtime_support() {
        for id in [
            "zai",
            "zai-coding-cn",
            "qwen-token-plan",
            "qwen-token-plan-cn",
            "qwen-token-plan-individual",
        ] {
            let entry = provider_catalog_entry(id).expect("catalog provider");
            assert_eq!(entry.quota, ProviderQuotaPolicyV1::SubscriptionWindow);
            assert_eq!(
                entry.implementation,
                ProviderImplementationStatusV1::Implemented
            );
        }
    }

    #[test]
    fn protocol_and_auth_options_follow_provider_shapes() {
        let radius = provider_catalog_entry("radius").expect("radius");
        assert_eq!(radius.protocol, ProviderProtocolV1::PiMessages);
        assert!(radius.supports_auth(ProviderAuthKindV1::ApiKey));
        assert!(radius.supports_auth(ProviderAuthKindV1::OAuth));

        let xai = provider_catalog_entry("xai").expect("xai");
        assert_eq!(xai.protocol, ProviderProtocolV1::Responses);
        assert!(xai.supports_auth(ProviderAuthKindV1::OAuth));

        let opencode = provider_catalog_entry("opencode").expect("opencode");
        assert_eq!(opencode.quota, ProviderQuotaPolicyV1::Payg);
    }

    #[test]
    fn extra_chat_profiles_are_authoritative_and_selectable() {
        for id in ["fireworks", "mistral", "opencode-go"] {
            let entry = provider_catalog_entry(id).expect("extra Chat provider");
            assert_eq!(entry.protocol, ProviderProtocolV1::ChatCompletions);
            assert_eq!(
                entry.implementation,
                ProviderImplementationStatusV1::Implemented
            );
            assert!(entry.supports_auth(ProviderAuthKindV1::ApiKey));
        }
    }

    #[test]
    fn snapshot_is_closed_and_contains_no_secret_or_endpoint_fields() {
        let snapshots = provider_catalog_snapshot();
        assert_eq!(snapshots.len(), 40);
        let json = serde_json::to_value(&snapshots).expect("snapshot JSON");
        let first = json.as_array().expect("snapshot array")[0]
            .as_object()
            .expect("snapshot object");
        assert!(first.contains_key("providerId"));
        assert!(first.contains_key("displayName"));
        assert!(!first.contains_key("endpoint"));
        assert!(!first.contains_key("credential"));
        assert!(
            serde_json::from_value::<Vec<ProviderCatalogSnapshotV1>>(serde_json::json!([{
                "providerId": "openai",
                "displayName": "OpenAI",
                "protocol": "responses",
                "authOptions": ["api_key"],
                "quota": "payg",
                "implementation": "implemented",
                "secret": "should reject"
            }]))
            .is_err()
        );
    }
}
