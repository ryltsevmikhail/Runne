/// Closed provider credential identities supported by native profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialId {
    /// `OpenAI` Responses API credential.
    OpenAi,
    /// Separately enrolled `OpenAI` background Responses API credential.
    OpenAiBackground,
    /// `DeepSeek` Responses API credential.
    DeepSeek,
    /// Z.ai Coding Plan credential.
    Zai,
    /// `QwenCloud` Token Plan credential.
    QwenTokenPlanIndividual,
    /// Local Engine launch-authority credential (non-secret marker).
    LocalEngine,
    /// Catalog-backed credential isolated by its exact provider ID.
    Generic(&'static str),
}

impl ProviderCredentialId {
    /// Resolves a closed provider account without accepting arbitrary IDs.
    #[must_use]
    pub fn from_account(account: &str) -> Option<Self> {
        match account {
            "openai" => Some(Self::OpenAi),
            "openai-background" => Some(Self::OpenAiBackground),
            "deepseek" => Some(Self::DeepSeek),
            "zai" => Some(Self::Zai),
            "qwen-token-plan-individual" => Some(Self::QwenTokenPlanIndividual),
            "local-engine" => Some(Self::LocalEngine),
            "anthropic" => Some(Self::Generic("anthropic")),
            "ant-ling" => Some(Self::Generic("ant-ling")),
            "azure-openai-responses" => Some(Self::Generic("azure-openai-responses")),
            "baseten" => Some(Self::Generic("baseten")),
            "cerebras" => Some(Self::Generic("cerebras")),
            "amazon-bedrock" => Some(Self::Generic("amazon-bedrock")),
            "google" => Some(Self::Generic("google")),
            "cloudflare-ai-gateway" => Some(Self::Generic("cloudflare-ai-gateway")),
            "cloudflare-workers-ai" => Some(Self::Generic("cloudflare-workers-ai")),
            "fireworks" => Some(Self::Generic("fireworks")),
            "groq" => Some(Self::Generic("groq")),
            "huggingface" => Some(Self::Generic("huggingface")),
            "moonshotai" => Some(Self::Generic("moonshotai")),
            "moonshotai-cn" => Some(Self::Generic("moonshotai-cn")),
            "mistral" => Some(Self::Generic("mistral")),
            "nvidia" => Some(Self::Generic("nvidia")),
            "together" => Some(Self::Generic("together")),
            "xiaomi" => Some(Self::Generic("xiaomi")),
            "xai" => Some(Self::Generic("xai")),
            "openai-codex" => Some(Self::Generic("openai-codex")),
            "github-copilot" => Some(Self::Generic("github-copilot")),
            "google-vertex" => Some(Self::Generic("google-vertex")),
            "vercel-ai-gateway" => Some(Self::Generic("vercel-ai-gateway")),
            "radius" => Some(Self::Generic("radius")),
            "kimi-coding" => Some(Self::Generic("kimi-coding")),
            "minimax" => Some(Self::Generic("minimax")),
            "minimax-cn" => Some(Self::Generic("minimax-cn")),
            "xiaomi-token-plan-ams" => Some(Self::Generic("xiaomi-token-plan-ams")),
            "xiaomi-token-plan-cn" => Some(Self::Generic("xiaomi-token-plan-cn")),
            "xiaomi-token-plan-sgp" => Some(Self::Generic("xiaomi-token-plan-sgp")),
            "zai-coding-cn" => Some(Self::Generic("zai-coding-cn")),
            "qwen-token-plan" => Some(Self::Generic("qwen-token-plan")),
            "qwen-token-plan-cn" => Some(Self::Generic("qwen-token-plan-cn")),
            "openrouter" => Some(Self::Generic("openrouter")),
            "opencode" => Some(Self::Generic("opencode")),
            "opencode-go" => Some(Self::Generic("opencode-go")),
            _ => None,
        }
    }

    /// Returns the fixed, non-secret native-store account.
    #[must_use]
    pub const fn account(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenAiBackground => "openai-background",
            Self::DeepSeek => "deepseek",
            Self::Zai => "zai",
            Self::QwenTokenPlanIndividual => "qwen-token-plan-individual",
            Self::LocalEngine => "local-engine",
            Self::Generic(provider) => provider,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderCredentialId;

    #[test]
    fn extra_chat_accounts_are_closed_and_round_trip() {
        for account in [
            "anthropic",
            "ant-ling",
            "azure-openai-responses",
            "openai",
            "openai-background",
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
        ] {
            let provider = ProviderCredentialId::from_account(account).expect("closed account");
            assert_eq!(provider.account(), account);
        }
        assert!(ProviderCredentialId::from_account("fireworks/other").is_none());
        assert_ne!(
            ProviderCredentialId::from_account("openai-background"),
            ProviderCredentialId::from_account("openai")
        );
    }
}
