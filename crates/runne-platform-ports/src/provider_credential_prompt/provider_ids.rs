use std::str::FromStr;

/// Closed catalog identities using the generic host credential prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPromptCatalogId {
    Anthropic,
    AntLing,
    AzureOpenAiResponses,
    Nvidia,
    Google,
    AmazonBedrock,
    Mistral,
    Groq,
    Cerebras,
    CloudflareAiGateway,
    CloudflareWorkersAi,
    Xai,
    OpenRouter,
    VercelAiGateway,
    Zai,
    ZaiCodingCn,
    OpenAiCodex,
    GithubCopilot,
    GoogleVertex,
    OpenCode,
    OpenCodeGo,
    Radius,
    HuggingFace,
    Fireworks,
    Together,
    Baseten,
    KimiCoding,
    MiniMax,
    MiniMaxCn,
    MoonshotAi,
    MoonshotAiCn,
    QwenTokenPlan,
    QwenTokenPlanIndividual,
    QwenTokenPlanCn,
    Xiaomi,
    XiaomiTokenPlanCn,
    XiaomiTokenPlanAms,
    XiaomiTokenPlanSgp,
}

impl CredentialPromptCatalogId {
    /// Resolves a closed catalog ID, rejecting arbitrary prompt labels.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "anthropic" => Self::Anthropic,
            "ant-ling" => Self::AntLing,
            "azure-openai-responses" => Self::AzureOpenAiResponses,
            "nvidia" => Self::Nvidia,
            "google" => Self::Google,
            "amazon-bedrock" => Self::AmazonBedrock,
            "mistral" => Self::Mistral,
            "groq" => Self::Groq,
            "cerebras" => Self::Cerebras,
            "cloudflare-ai-gateway" => Self::CloudflareAiGateway,
            "cloudflare-workers-ai" => Self::CloudflareWorkersAi,
            "xai" => Self::Xai,
            "openrouter" => Self::OpenRouter,
            "vercel-ai-gateway" => Self::VercelAiGateway,
            "zai" => Self::Zai,
            "zai-coding-cn" => Self::ZaiCodingCn,
            "openai-codex" => Self::OpenAiCodex,
            "github-copilot" => Self::GithubCopilot,
            "google-vertex" => Self::GoogleVertex,
            "opencode" => Self::OpenCode,
            "opencode-go" => Self::OpenCodeGo,
            "radius" => Self::Radius,
            "huggingface" => Self::HuggingFace,
            "fireworks" => Self::Fireworks,
            "together" => Self::Together,
            "baseten" => Self::Baseten,
            "kimi-coding" => Self::KimiCoding,
            "minimax" => Self::MiniMax,
            "minimax-cn" => Self::MiniMaxCn,
            "moonshotai" => Self::MoonshotAi,
            "moonshotai-cn" => Self::MoonshotAiCn,
            "qwen-token-plan" => Self::QwenTokenPlan,
            "qwen-token-plan-individual" => Self::QwenTokenPlanIndividual,
            "qwen-token-plan-cn" => Self::QwenTokenPlanCn,
            "xiaomi" => Self::Xiaomi,
            "xiaomi-token-plan-cn" => Self::XiaomiTokenPlanCn,
            "xiaomi-token-plan-ams" => Self::XiaomiTokenPlanAms,
            "xiaomi-token-plan-sgp" => Self::XiaomiTokenPlanSgp,
            _ => return None,
        })
    }

    /// Returns a non-secret prompt label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::AntLing => "Ant Ling",
            Self::AzureOpenAiResponses => "Azure OpenAI Responses",
            Self::Nvidia => "NVIDIA",
            Self::Google => "Google",
            Self::AmazonBedrock => "Amazon Bedrock",
            Self::Mistral => "Mistral",
            Self::Groq => "Groq",
            Self::Cerebras => "Cerebras",
            Self::CloudflareAiGateway => "Cloudflare AI Gateway",
            Self::CloudflareWorkersAi => "Cloudflare Workers AI",
            Self::Xai => "xAI",
            Self::OpenRouter => "OpenRouter",
            Self::VercelAiGateway => "Vercel AI Gateway",
            Self::Zai => "Z.AI",
            Self::ZaiCodingCn => "Z.AI Coding CN",
            Self::OpenAiCodex => "OpenAI Codex",
            Self::GithubCopilot => "GitHub Copilot",
            Self::GoogleVertex => "Google Vertex AI",
            Self::OpenCode => "OpenCode Zen",
            Self::OpenCodeGo => "OpenCode Go",
            Self::Radius => "Radius",
            Self::HuggingFace => "Hugging Face",
            Self::Fireworks => "Fireworks",
            Self::Together => "Together AI",
            Self::Baseten => "Baseten",
            Self::KimiCoding => "Kimi For Coding",
            Self::MiniMax => "MiniMax",
            Self::MiniMaxCn => "MiniMax CN",
            Self::MoonshotAi => "Moonshot AI",
            Self::MoonshotAiCn => "Moonshot AI CN",
            Self::QwenTokenPlan => "Qwen Token Plan",
            Self::QwenTokenPlanIndividual => "Qwen Token Plan Individual",
            Self::QwenTokenPlanCn => "Qwen Token Plan CN",
            Self::Xiaomi => "Xiaomi MiMo",
            Self::XiaomiTokenPlanCn => "Xiaomi MiMo Token Plan CN",
            Self::XiaomiTokenPlanAms => "Xiaomi MiMo Token Plan Amsterdam",
            Self::XiaomiTokenPlanSgp => "Xiaomi MiMo Token Plan Singapore",
        }
    }
}

impl FromStr for CredentialPromptCatalogId {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialPromptCatalogId;

    #[test]
    fn only_closed_catalog_ids_can_be_prompted() {
        for id in [
            "anthropic",
            "ant-ling",
            "azure-openai-responses",
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
            assert!(CredentialPromptCatalogId::parse(id).is_some(), "{id}");
        }
        assert!(CredentialPromptCatalogId::parse("unknown-provider").is_none());
        assert!(CredentialPromptCatalogId::parse("openai").is_none());
    }
}
