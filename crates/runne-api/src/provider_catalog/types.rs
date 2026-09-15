//! Stable types shared by the closed provider catalog.

use serde::{Deserialize, Serialize};

/// Protocol family used by a provider adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProtocolV1 {
    /// OpenAI Responses API.
    Responses,
    /// OpenAI-compatible Chat Completions API.
    ChatCompletions,
    /// Anthropic Messages API.
    AnthropicMessages,
    /// Google Gemini or Vertex API.
    Gemini,
    /// AWS Bedrock runtime API.
    Bedrock,
    /// Runne Pi Messages gateway API.
    PiMessages,
    /// A gateway with more than one model API family.
    MultiProtocol,
}

/// Credential family accepted by a native provider adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthKindV1 {
    /// No credential is required.
    None,
    /// Bearer or API key material held by the native secure store.
    ApiKey,
    /// OAuth material held by the native secure store.
    OAuth,
    /// AWS signing material held by a native broker.
    Aws,
}

/// Provider billing and quota posture. A posture does not prove live quota.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQuotaPolicyV1 {
    /// The provider account is subscription based and has provider limits.
    SubscriptionWindow,
    /// The provider is normally pay as you go.
    Payg,
    /// The billing or quota posture is not qualified yet.
    Unqualified,
}

/// Runtime support qualification independent from catalog metadata.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderImplementationStatusV1 {
    /// Identity and protocol metadata are catalogued only.
    CatalogOnly,
    /// A native adapter exists, but live qualification is pending.
    Implemented,
    /// A native adapter passed the authenticated live qualification gate.
    LiveQualified,
}

/// Closed daemon route classification for a catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCatalogRouteV1 {
    /// Existing OpenAI Responses effect.
    OpenAiResponses,
    /// Existing DeepSeek Responses effect.
    DeepSeekResponses,
    /// Dedicated Z.ai Coding Plan Chat route.
    ZaiCodingChat,
    /// Dedicated Qwen Token Plan Chat route.
    QwenTokenPlanChat,
    /// Generic validated Chat Completions route.
    GenericChat,
    /// Native Anthropic/Gemini family route.
    Native,
    /// Dynamic Responses route.
    Responses,
    /// Dynamic configured Cloud Chat route.
    Cloud,
    /// Dynamic Pi Radius route.
    Radius,
    /// Catalog metadata without a selected daemon route.
    CatalogOnly,
}

/// Non-secret provider metadata returned by the authoritative backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCatalogEntryV1 {
    /// Stable provider identifier from the Pi provider catalog.
    pub provider_id: &'static str,
    /// Protocol family used by the adapter.
    pub protocol: ProviderProtocolV1,
    /// Primary credential family used for display and policy decisions.
    pub auth: ProviderAuthKindV1,
    /// All credential families available to a future adapter.
    pub auth_options: &'static [ProviderAuthKindV1],
    /// Billing and quota posture; it does not report remaining quota.
    pub quota: ProviderQuotaPolicyV1,
    /// Backend implementation qualification.
    pub implementation: ProviderImplementationStatusV1,
}

/// Renderer-safe catalog projection. It contains no endpoint or credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderCatalogSnapshotV1 {
    /// Stable provider identifier.
    pub provider_id: String,
    /// Human-readable provider label sourced from the provider catalog.
    pub display_name: String,
    /// Protocol family metadata.
    pub protocol: ProviderProtocolV1,
    /// Accepted credential families.
    pub auth_options: Vec<ProviderAuthKindV1>,
    /// Billing and quota posture, without remaining quota claims.
    pub quota: ProviderQuotaPolicyV1,
    /// Backend support qualification.
    pub implementation: ProviderImplementationStatusV1,
}

impl ProviderCatalogEntryV1 {
    /// Returns the exact closed route selected by the daemon.
    #[must_use]
    pub fn route(self) -> ProviderCatalogRouteV1 {
        match self.provider_id {
            "openai" => ProviderCatalogRouteV1::OpenAiResponses,
            "deepseek" => ProviderCatalogRouteV1::DeepSeekResponses,
            "zai" => ProviderCatalogRouteV1::ZaiCodingChat,
            "qwen-token-plan-individual" => ProviderCatalogRouteV1::QwenTokenPlanChat,
            "amazon-bedrock" | "cloudflare-ai-gateway" | "cloudflare-workers-ai" | "nvidia" => {
                ProviderCatalogRouteV1::Cloud
            }
            "openai-codex" | "github-copilot" | "azure-openai-responses" | "xai" => {
                ProviderCatalogRouteV1::Responses
            }
            "anthropic" | "google" | "google-vertex" | "kimi-coding" | "minimax" | "minimax-cn"
            | "vercel-ai-gateway" => ProviderCatalogRouteV1::Native,
            "radius" => ProviderCatalogRouteV1::Radius,
            "ant-ling"
            | "baseten"
            | "cerebras"
            | "fireworks"
            | "groq"
            | "huggingface"
            | "mistral"
            | "moonshotai"
            | "moonshotai-cn"
            | "opencode"
            | "opencode-go"
            | "openrouter"
            | "qwen-token-plan"
            | "qwen-token-plan-cn"
            | "together"
            | "xiaomi"
            | "xiaomi-token-plan-ams"
            | "xiaomi-token-plan-cn"
            | "xiaomi-token-plan-sgp"
            | "zai-coding-cn" => ProviderCatalogRouteV1::GenericChat,
            _ => ProviderCatalogRouteV1::CatalogOnly,
        }
    }

    /// Returns whether a native adapter is available for this provider.
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        !matches!(
            self.implementation,
            ProviderImplementationStatusV1::CatalogOnly
        )
    }

    /// Returns whether authenticated live qualification succeeded.
    #[must_use]
    pub const fn is_live_qualified(self) -> bool {
        matches!(
            self.implementation,
            ProviderImplementationStatusV1::LiveQualified
        )
    }

    /// Returns whether a credential family is supported by the metadata.
    #[must_use]
    pub fn supports_auth(self, kind: ProviderAuthKindV1) -> bool {
        self.auth_options.contains(&kind)
    }
}
