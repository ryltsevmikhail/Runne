use super::{
    ConfiguredChatModelLimits, ConfiguredChatProfile, ConfiguredChatProfileError,
    ConfiguredChatProvider, REVISION, validate_gateway_billing, validate_payg,
};
use crate::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsProfile,
    ChatCompletionsThinkingMode,
};

/// Builds a configured Bedrock profile with explicit model limits.
///
/// # Errors
/// Returns an error for unsafe components, invalid limits, or unsupported billing.
pub fn bedrock_with_limits(
    region: &str,
    model: impl Into<String>,
    accounting: ChatCompletionsAccounting,
    limits: ConfiguredChatModelLimits,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(region) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    finish(
        ConfiguredChatProvider::AmazonBedrock,
        format!("https://bedrock-runtime.{region}.amazonaws.com"),
        "/v1/chat/completions".into(),
        model.into(),
        accounting,
        limits,
        ChatCompletionsBillingMode::ExternalPayg,
        ChatCompletionsThinkingMode::None,
    )
}

/// Legacy constructor that fails closed because arbitrary models have no limits.
///
/// # Errors
/// Always returns `MissingLimits` for valid components.
pub fn bedrock(
    region: &str,
    model: impl Into<String>,
    _accounting: ChatCompletionsAccounting,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(region) || !model_component(&model.into()) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    Err(ConfiguredChatProfileError::MissingLimits)
}

/// Builds a configured Workers AI profile with explicit model limits.
///
/// # Errors
/// Returns an error for unsafe components, invalid limits, or unsupported billing.
pub fn cloudflare_workers_with_limits(
    account: &str,
    model: impl Into<String>,
    accounting: ChatCompletionsAccounting,
    limits: ConfiguredChatModelLimits,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(account) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    finish(
        ConfiguredChatProvider::CloudflareWorkersAi,
        "https://api.cloudflare.com".into(),
        format!("/client/v4/accounts/{account}/ai/v1/chat/completions"),
        model.into(),
        accounting,
        limits,
        ChatCompletionsBillingMode::ExternalPayg,
        ChatCompletionsThinkingMode::None,
    )
}

/// Legacy constructor that fails closed because arbitrary models have no limits.
///
/// # Errors
/// Always returns `MissingLimits` for valid components.
pub fn cloudflare_workers(
    account: &str,
    model: impl Into<String>,
    _accounting: ChatCompletionsAccounting,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(account) || !model_component(&model.into()) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    Err(ConfiguredChatProfileError::MissingLimits)
}

/// Builds a configured AI Gateway profile with an explicit billing route.
///
/// # Errors
/// Returns an error for unsafe components, invalid limits, billing, or rates.
pub fn cloudflare_gateway_with_limits(
    account: &str,
    gateway: &str,
    model: impl Into<String>,
    accounting: ChatCompletionsAccounting,
    billing_mode: ChatCompletionsBillingMode,
    limits: ConfiguredChatModelLimits,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(account) || !component(gateway) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    validate_gateway_billing(billing_mode)?;
    finish(
        ConfiguredChatProvider::CloudflareAiGateway,
        "https://gateway.ai.cloudflare.com".into(),
        format!("/v1/{account}/{gateway}/compat/chat/completions"),
        model.into(),
        accounting,
        limits,
        billing_mode,
        ChatCompletionsThinkingMode::None,
    )
}

/// Legacy constructor that fails closed because model limits and billing route are absent.
///
/// # Errors
/// Always returns `MissingLimits` for valid components.
pub fn cloudflare_gateway(
    account: &str,
    gateway: &str,
    model: impl Into<String>,
    _accounting: ChatCompletionsAccounting,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !component(account) || !component(gateway) || !model_component(&model.into()) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    Err(ConfiguredChatProfileError::MissingLimits)
}

/// Builds a configured NVIDIA profile with explicit model limits and PAYG rates.
///
/// # Errors
/// Returns an error for an invalid model, limits, or PAYG quote.
pub fn nvidia_with_limits(
    model: impl Into<String>,
    accounting: ChatCompletionsAccounting,
    limits: ConfiguredChatModelLimits,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    finish(
        ConfiguredChatProvider::Nvidia,
        "https://integrate.api.nvidia.com".into(),
        "/v1/chat/completions".into(),
        model.into(),
        accounting,
        limits,
        ChatCompletionsBillingMode::ExternalPayg,
        ChatCompletionsThinkingMode::None,
    )
}

/// Legacy constructor that fails closed because arbitrary models have no limits.
///
/// # Errors
/// Always returns `MissingLimits` for valid models.
pub fn nvidia(
    model: impl Into<String>,
    _accounting: ChatCompletionsAccounting,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !model_component(&model.into()) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    Err(ConfiguredChatProfileError::MissingLimits)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    provider: ConfiguredChatProvider,
    origin: String,
    path: String,
    model_id: String,
    accounting: ChatCompletionsAccounting,
    limits: ConfiguredChatModelLimits,
    billing_mode: ChatCompletionsBillingMode,
    thinking: ChatCompletionsThinkingMode,
) -> Result<ConfiguredChatProfile, ConfiguredChatProfileError> {
    if !model_component(&model_id) {
        return Err(ConfiguredChatProfileError::InvalidComponent);
    }
    if !limits.validate() {
        return Err(ConfiguredChatProfileError::InvalidLimits);
    }
    validate_payg(accounting)?;
    let provider_id = match provider {
        ConfiguredChatProvider::AmazonBedrock => "amazon-bedrock",
        ConfiguredChatProvider::CloudflareWorkersAi => "cloudflare-workers-ai",
        ConfiguredChatProvider::CloudflareAiGateway => "cloudflare-ai-gateway",
        ConfiguredChatProvider::Nvidia => "nvidia",
    };
    let profile_id = format!("gocode-chat-completions/{provider_id}/configured/1");
    let profile = ChatCompletionsProfile::new_owned_with_accounting(
        provider_id.to_owned(),
        profile_id,
        model_id,
        REVISION.to_owned(),
        origin,
        path,
        [0; 32],
        [0; 32],
        limits.max_input_entries(),
        limits.max_input_entry_bytes(),
        limits.max_input_bytes(),
        limits.max_output_tokens(),
        limits.max_request_bytes(),
        limits.max_response_frame_bytes(),
        limits.model(),
        billing_mode,
        accounting,
        thinking,
    )
    .with_recomputed_digests();
    profile
        .validate()
        .map_err(|_| ConfiguredChatProfileError::InvalidLimits)?;
    Ok(ConfiguredChatProfile {
        provider,
        billing_mode,
        profile,
    })
}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn model_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
}
