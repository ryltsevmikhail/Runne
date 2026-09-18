//! Exact Pi provider IDs and non-secret backend qualification metadata.

use super::types::{
    ProviderAuthKindV1, ProviderCatalogEntryV1, ProviderImplementationStatusV1, ProviderProtocolV1,
    ProviderQuotaPolicyV1,
};

const API_KEY: &[ProviderAuthKindV1] = &[ProviderAuthKindV1::ApiKey];
const OAUTH: &[ProviderAuthKindV1] = &[ProviderAuthKindV1::OAuth];
const API_KEY_OAUTH: &[ProviderAuthKindV1] =
    &[ProviderAuthKindV1::ApiKey, ProviderAuthKindV1::OAuth];
const API_KEY_AWS: &[ProviderAuthKindV1] = &[ProviderAuthKindV1::ApiKey, ProviderAuthKindV1::Aws];
const CATALOG: ProviderImplementationStatusV1 = ProviderImplementationStatusV1::CatalogOnly;
const IMPLEMENTED: ProviderImplementationStatusV1 = ProviderImplementationStatusV1::Implemented;

const fn entry(
    provider_id: &'static str,
    protocol: ProviderProtocolV1,
    auth_options: &'static [ProviderAuthKindV1],
    quota: ProviderQuotaPolicyV1,
    implementation: ProviderImplementationStatusV1,
) -> ProviderCatalogEntryV1 {
    ProviderCatalogEntryV1 {
        provider_id,
        protocol,
        auth: auth_options[0],
        auth_options,
        quota,
        implementation,
    }
}

macro_rules! provider {
    ($id:literal, $protocol:ident, $auth:ident, $quota:ident, $status:ident) => {
        entry(
            $id,
            ProviderProtocolV1::$protocol,
            $auth,
            ProviderQuotaPolicyV1::$quota,
            $status,
        )
    };
}

// Pi's image-only openrouter-images provider is intentionally outside text runtime.
pub(super) const CATALOG_ENTRIES: &[ProviderCatalogEntryV1] = &[
    provider!("amazon-bedrock", Bedrock, API_KEY_AWS, Unqualified, CATALOG),
    provider!(
        "ant-ling",
        ChatCompletions,
        API_KEY,
        Unqualified,
        IMPLEMENTED
    ),
    provider!(
        "anthropic",
        AnthropicMessages,
        API_KEY_OAUTH,
        Unqualified,
        CATALOG
    ),
    provider!(
        "azure-openai-responses",
        Responses,
        API_KEY,
        Unqualified,
        CATALOG
    ),
    provider!("baseten", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("cerebras", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!(
        "cloudflare-ai-gateway",
        ChatCompletions,
        API_KEY,
        Unqualified,
        CATALOG
    ),
    provider!(
        "cloudflare-workers-ai",
        ChatCompletions,
        API_KEY,
        Unqualified,
        CATALOG
    ),
    provider!("deepseek", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("fireworks", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("github-copilot", MultiProtocol, OAUTH, Unqualified, CATALOG),
    provider!("google", Gemini, API_KEY, Unqualified, CATALOG),
    provider!("google-vertex", Gemini, API_KEY, Unqualified, CATALOG),
    provider!("groq", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("huggingface", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!(
        "kimi-coding",
        AnthropicMessages,
        API_KEY_OAUTH,
        SubscriptionWindow,
        CATALOG
    ),
    provider!("minimax", AnthropicMessages, API_KEY, Payg, CATALOG),
    provider!("minimax-cn", AnthropicMessages, API_KEY, Payg, CATALOG),
    provider!("mistral", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("moonshotai", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("moonshotai-cn", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!("nvidia", ChatCompletions, API_KEY, Unqualified, IMPLEMENTED),
    provider!("openai", Responses, API_KEY, Payg, IMPLEMENTED),
    provider!(
        "openai-codex",
        Responses,
        OAUTH,
        SubscriptionWindow,
        CATALOG
    ),
    provider!("opencode", MultiProtocol, API_KEY, Payg, IMPLEMENTED),
    provider!(
        "opencode-go",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "openrouter",
        MultiProtocol,
        API_KEY_OAUTH,
        Payg,
        IMPLEMENTED
    ),
    provider!(
        "qwen-token-plan",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "qwen-token-plan-cn",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "qwen-token-plan-individual",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!("radius", PiMessages, API_KEY_OAUTH, Unqualified, CATALOG),
    provider!("together", ChatCompletions, API_KEY, Payg, IMPLEMENTED),
    provider!(
        "vercel-ai-gateway",
        AnthropicMessages,
        API_KEY,
        Unqualified,
        CATALOG
    ),
    provider!("xai", Responses, API_KEY_OAUTH, Unqualified, CATALOG),
    provider!("xiaomi", ChatCompletions, API_KEY, Unqualified, IMPLEMENTED),
    provider!(
        "xiaomi-token-plan-ams",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "xiaomi-token-plan-cn",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "xiaomi-token-plan-sgp",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "zai",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
    provider!(
        "zai-coding-cn",
        ChatCompletions,
        API_KEY,
        SubscriptionWindow,
        IMPLEMENTED
    ),
];
