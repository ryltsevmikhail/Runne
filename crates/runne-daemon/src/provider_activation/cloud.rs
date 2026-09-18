//! Configured Chat Completions profiles for the closed cloud routes.

use super::ProviderActivationSettings;
use runne_daemon_chat_completions_effect::ChatCompletionsAuthHeader;
use runne_provider_chat_completions::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsProfile,
    ConfiguredChatModelLimits, bedrock_with_limits, cloudflare_gateway_with_limits,
    cloudflare_workers_with_limits, nvidia_with_limits,
};

pub(crate) fn configured_profile(
    profile_id: &str,
    settings: &ProviderActivationSettings,
) -> Result<(ChatCompletionsProfile, ChatCompletionsAuthHeader), &'static str> {
    let (provider, model) = parse_profile(profile_id)?;
    let limits = configured_limits(settings)?;
    let accounting = configured_accounting(settings)?;
    let configured = match provider {
        "amazon-bedrock" => bedrock_with_limits(
            settings
                .cloud_region_or_account
                .as_deref()
                .ok_or("Bedrock region is required")?,
            model,
            accounting,
            limits,
        ),
        "cloudflare-workers-ai" => cloudflare_workers_with_limits(
            settings
                .cloud_region_or_account
                .as_deref()
                .ok_or("Cloudflare account is required")?,
            model,
            accounting,
            limits,
        ),
        "cloudflare-ai-gateway" => cloudflare_gateway_with_limits(
            settings
                .cloud_region_or_account
                .as_deref()
                .ok_or("Cloudflare account is required")?,
            settings
                .cloud_gateway
                .as_deref()
                .ok_or("Cloudflare gateway is required")?,
            model,
            accounting,
            gateway_billing(settings)?,
            limits,
        ),
        "nvidia" => nvidia_with_limits(model, accounting, limits),
        _ => return Err("Cloud profile is not in the closed registry"),
    }
    .map_err(|_| "Cloud profile configuration is invalid")?;
    let profile = rename_profile(configured.into_profile(), profile_id)?;
    let auth = if provider == "cloudflare-ai-gateway" {
        ChatCompletionsAuthHeader::CloudflareAiGateway
    } else {
        ChatCompletionsAuthHeader::Authorization
    };
    Ok((profile, auth))
}

fn parse_profile(profile_id: &str) -> Result<(&str, &str), &'static str> {
    let rest = profile_id
        .strip_prefix("gocode-cloud/")
        .ok_or("invalid Cloud profile prefix")?;
    let body = rest
        .strip_suffix("/1")
        .ok_or("invalid Cloud profile revision")?;
    let (provider, model) = body.split_once('/').ok_or("Cloud model is required")?;
    if model.is_empty()
        || model.len() > 256
        || !model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        })
    {
        return Err("invalid Cloud model");
    }
    if !matches!(
        provider,
        "amazon-bedrock" | "cloudflare-workers-ai" | "cloudflare-ai-gateway" | "nvidia"
    ) {
        return Err("invalid Cloud provider");
    }
    Ok((provider, model))
}

fn configured_limits(
    settings: &ProviderActivationSettings,
) -> Result<ConfiguredChatModelLimits, &'static str> {
    let context = settings
        .cloud_context_tokens
        .ok_or("Cloud context bound is required")?;
    let output = settings
        .cloud_max_output_tokens
        .ok_or("Cloud output bound is required")?;
    let model_output = settings
        .cloud_max_model_output_tokens
        .ok_or("Cloud model output bound is required")?;
    let overhead = 256_u32;
    let input = context
        .checked_sub(model_output)
        .and_then(|value| value.checked_sub(overhead))
        .ok_or("Cloud model bounds are invalid")?;
    let limits = ConfiguredChatModelLimits::new(
        context,
        input,
        model_output,
        output,
        overhead,
        settings
            .cloud_max_input_entries
            .ok_or("Cloud input entry bound is required")?,
        settings
            .cloud_max_input_entry_bytes
            .ok_or("Cloud input entry bytes are required")?,
        settings
            .cloud_max_input_bytes
            .ok_or("Cloud input bytes are required")?,
        settings
            .cloud_max_request_bytes
            .ok_or("Cloud request bytes are required")?,
        settings
            .cloud_max_response_frame_bytes
            .ok_or("Cloud response frame bytes are required")?,
    );
    Ok(limits)
}

fn configured_accounting(
    settings: &ProviderActivationSettings,
) -> Result<ChatCompletionsAccounting, &'static str> {
    if !matches!(
        settings.accounting_mode,
        Some(super::ProviderAccountingMode::Payg)
    ) {
        return Err("Cloud routes require explicit PAYG accounting");
    }
    Ok(ChatCompletionsAccounting::Payg {
        input_micros_per_million: settings
            .cloud_input_micros_per_million
            .ok_or("Cloud input price is required")?,
        output_micros_per_million: settings
            .cloud_output_micros_per_million
            .ok_or("Cloud output price is required")?,
        cached_input_micros_per_million: settings
            .cloud_cached_input_micros_per_million
            .unwrap_or(0),
    })
}

fn gateway_billing(
    settings: &ProviderActivationSettings,
) -> Result<ChatCompletionsBillingMode, &'static str> {
    match settings.cloud_gateway_billing.as_deref() {
        Some("unified_billing") => Ok(ChatCompletionsBillingMode::UnifiedBilling),
        Some("stored_byok") => Ok(ChatCompletionsBillingMode::StoredByok),
        _ => Err("Cloudflare Gateway billing route is required"),
    }
}

fn rename_profile(
    profile: ChatCompletionsProfile,
    profile_id: &str,
) -> Result<ChatCompletionsProfile, &'static str> {
    let limits = profile
        .model_limits()
        .ok_or("Cloud model limits are missing")?;
    let billing = profile
        .billing_mode()
        .ok_or("Cloud billing mode is missing")?;
    Ok(ChatCompletionsProfile::new_owned_with_accounting(
        profile.provider_id().to_owned(),
        profile_id.to_owned(),
        profile.model_id().to_owned(),
        profile.model_revision().to_owned(),
        profile.origin().to_owned(),
        profile.path().to_owned(),
        [0; 32],
        [0; 32],
        profile.max_input_entries(),
        profile.max_input_entry_bytes(),
        profile.max_input_bytes(),
        profile.max_output_tokens(),
        profile.max_request_bytes(),
        profile.max_frame_bytes(),
        limits,
        billing,
        profile.accounting(),
        profile.thinking_mode(),
    )
    .with_recomputed_digests())
}
