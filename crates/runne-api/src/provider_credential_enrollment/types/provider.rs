use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Closed credential identities accepted by protected enrollment V2.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderCredentialProviderV2 {
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "ant-ling")]
    AntLing,
    #[serde(rename = "azure-openai-responses")]
    AzureOpenAiResponses,
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "deepseek")]
    DeepSeek,
    #[serde(rename = "nvidia")]
    Nvidia,
    #[serde(rename = "google")]
    Google,
    #[serde(rename = "amazon-bedrock")]
    AmazonBedrock,
    #[serde(rename = "mistral")]
    Mistral,
    #[serde(rename = "groq")]
    Groq,
    #[serde(rename = "cerebras")]
    Cerebras,
    #[serde(rename = "cloudflare-ai-gateway")]
    CloudflareAiGateway,
    #[serde(rename = "cloudflare-workers-ai")]
    CloudflareWorkersAi,
    #[serde(rename = "xai")]
    Xai,
    #[serde(rename = "openrouter")]
    OpenRouter,
    #[serde(rename = "vercel-ai-gateway")]
    VercelAiGateway,
    #[serde(rename = "zai")]
    Zai,
    #[serde(rename = "zai-coding-cn")]
    ZaiCodingCn,
    #[serde(rename = "openai-codex")]
    OpenAiCodex,
    #[serde(rename = "github-copilot")]
    GithubCopilot,
    #[serde(rename = "google-vertex")]
    GoogleVertex,
    #[serde(rename = "opencode")]
    OpenCode,
    #[serde(rename = "opencode-go")]
    OpenCodeGo,
    #[serde(rename = "radius")]
    Radius,
    #[serde(rename = "huggingface")]
    HuggingFace,
    #[serde(rename = "fireworks")]
    Fireworks,
    #[serde(rename = "together")]
    Together,
    #[serde(rename = "baseten")]
    Baseten,
    #[serde(rename = "kimi-coding")]
    KimiCoding,
    #[serde(rename = "minimax")]
    MiniMax,
    #[serde(rename = "minimax-cn")]
    MiniMaxCn,
    #[serde(rename = "moonshotai")]
    MoonshotAi,
    #[serde(rename = "moonshotai-cn")]
    MoonshotAiCn,
    #[serde(rename = "qwen-token-plan")]
    QwenTokenPlan,
    #[serde(rename = "qwen-token-plan-individual")]
    QwenTokenPlanIndividual,
    #[serde(rename = "qwen-token-plan-cn")]
    QwenTokenPlanCn,
    #[serde(rename = "xiaomi")]
    Xiaomi,
    #[serde(rename = "xiaomi-token-plan-cn")]
    XiaomiTokenPlanCn,
    #[serde(rename = "xiaomi-token-plan-ams")]
    XiaomiTokenPlanAms,
    #[serde(rename = "xiaomi-token-plan-sgp")]
    XiaomiTokenPlanSgp,
}

impl ProviderCredentialProviderV2 {
    /// Returns the canonical non-secret catalog identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::AntLing => "ant-ling",
            Self::AzureOpenAiResponses => "azure-openai-responses",
            Self::OpenAi => "openai",
            Self::DeepSeek => "deepseek",
            Self::Nvidia => "nvidia",
            Self::Google => "google",
            Self::AmazonBedrock => "amazon-bedrock",
            Self::Mistral => "mistral",
            Self::Groq => "groq",
            Self::Cerebras => "cerebras",
            Self::CloudflareAiGateway => "cloudflare-ai-gateway",
            Self::CloudflareWorkersAi => "cloudflare-workers-ai",
            Self::Xai => "xai",
            Self::OpenRouter => "openrouter",
            Self::VercelAiGateway => "vercel-ai-gateway",
            Self::Zai => "zai",
            Self::ZaiCodingCn => "zai-coding-cn",
            Self::OpenAiCodex => "openai-codex",
            Self::GithubCopilot => "github-copilot",
            Self::GoogleVertex => "google-vertex",
            Self::OpenCode => "opencode",
            Self::OpenCodeGo => "opencode-go",
            Self::Radius => "radius",
            Self::HuggingFace => "huggingface",
            Self::Fireworks => "fireworks",
            Self::Together => "together",
            Self::Baseten => "baseten",
            Self::KimiCoding => "kimi-coding",
            Self::MiniMax => "minimax",
            Self::MiniMaxCn => "minimax-cn",
            Self::MoonshotAi => "moonshotai",
            Self::MoonshotAiCn => "moonshotai-cn",
            Self::QwenTokenPlan => "qwen-token-plan",
            Self::QwenTokenPlanIndividual => "qwen-token-plan-individual",
            Self::QwenTokenPlanCn => "qwen-token-plan-cn",
            Self::Xiaomi => "xiaomi",
            Self::XiaomiTokenPlanCn => "xiaomi-token-plan-cn",
            Self::XiaomiTokenPlanAms => "xiaomi-token-plan-ams",
            Self::XiaomiTokenPlanSgp => "xiaomi-token-plan-sgp",
        }
    }

    /// Stable protected-envelope tag; values 1-4 preserve the released wire.
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::OpenAi => 1,
            Self::DeepSeek => 2,
            Self::Zai => 3,
            Self::QwenTokenPlanIndividual => 4,
            Self::Anthropic => 5,
            Self::AntLing => 6,
            Self::AzureOpenAiResponses => 7,
            Self::Nvidia => 8,
            Self::Google => 9,
            Self::AmazonBedrock => 10,
            Self::Mistral => 11,
            Self::Groq => 12,
            Self::Cerebras => 13,
            Self::CloudflareAiGateway => 14,
            Self::CloudflareWorkersAi => 15,
            Self::Xai => 16,
            Self::OpenRouter => 17,
            Self::VercelAiGateway => 18,
            Self::ZaiCodingCn => 19,
            Self::OpenAiCodex => 20,
            Self::GithubCopilot => 21,
            Self::GoogleVertex => 22,
            Self::OpenCode => 23,
            Self::OpenCodeGo => 24,
            Self::Radius => 25,
            Self::HuggingFace => 26,
            Self::Fireworks => 27,
            Self::Together => 28,
            Self::Baseten => 29,
            Self::KimiCoding => 30,
            Self::MiniMax => 31,
            Self::MiniMaxCn => 32,
            Self::MoonshotAi => 33,
            Self::MoonshotAiCn => 34,
            Self::QwenTokenPlan => 35,
            Self::QwenTokenPlanCn => 36,
            Self::Xiaomi => 37,
            Self::XiaomiTokenPlanCn => 38,
            Self::XiaomiTokenPlanAms => 39,
            Self::XiaomiTokenPlanSgp => 40,
        }
    }

    /// Resolves only one of the closed catalog identities.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "anthropic" => Self::Anthropic,
            "ant-ling" => Self::AntLing,
            "azure-openai-responses" => Self::AzureOpenAiResponses,
            "openai" => Self::OpenAi,
            "deepseek" => Self::DeepSeek,
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
}

impl FromStr for ProviderCredentialProviderV2 {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
