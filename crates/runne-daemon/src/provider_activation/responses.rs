use super::{ProviderAccountingMode, ProviderActivationSettings};
use runne_daemon_responses_effect::ResponsesAuth;
use runne_provider_responses_wire::{
    CODEX_SUBSCRIPTION_PRICING_DIGEST, COPILOT_SUBSCRIPTION_PRICING_DIGEST, ResponsesAccounting,
    ResponsesProfile, azure_profile, codex_subscription_profile, copilot_subscription_profile,
    xai_payg_profile,
};

pub(crate) const CODEX_PROFILE_ID: &str = "gocode-responses/openai-codex/gpt-5.5/1";
pub(crate) const COPILOT_PROFILE_ID: &str = "gocode-responses/github-copilot/gpt-5.3-codex/1";
pub(crate) const XAI_PROFILE_ID: &str = "gocode-responses/xai/grok-4.3/1";

pub(crate) fn configured_profile(
    profile_id: &str,
    settings: &ProviderActivationSettings,
) -> Result<(ResponsesProfile, ResponsesAuth), &'static str> {
    if profile_id == CODEX_PROFILE_ID {
        reject_unexpected_settings(settings)?;
        let profile = codex_subscription_profile(
            runne_provider_responses_wire::CODEX_MAX_OUTPUT_TOKENS,
            CODEX_SUBSCRIPTION_PRICING_DIGEST,
        );
        return Ok((
            profile,
            ResponsesAuth::Codex {
                account_id: "envelope".into(),
            },
        ));
    }
    if profile_id == COPILOT_PROFILE_ID {
        reject_unexpected_settings(settings)?;
        let profile = copilot_subscription_profile(
            runne_provider_responses_wire::COPILOT_MAX_OUTPUT_TOKENS,
            COPILOT_SUBSCRIPTION_PRICING_DIGEST,
        );
        return Ok((profile, ResponsesAuth::CopilotSession));
    }
    if profile_id == XAI_PROFILE_ID {
        if settings
            .accounting_mode
            .is_some_and(|mode| !matches!(mode, ProviderAccountingMode::Payg))
        {
            return Err("xAI Responses requires PAYG accounting");
        }
        let pricing = explicit_pricing(settings)?;
        let profile = xai_payg_profile(
            settings
                .responses_max_output_tokens
                .unwrap_or(runne_provider_responses_wire::XAI_MAX_OUTPUT_TOKENS),
            settings
                .responses_pricing_digest
                .ok_or("xAI pricing digest is required")?,
            pricing.0,
            pricing.1,
            pricing.2,
        );
        if profile.max_output_tokens() == 0
            || profile.max_output_tokens() > runne_provider_responses_wire::XAI_MAX_OUTPUT_TOKENS
        {
            return Err("xAI output bound exceeds the pinned model maximum");
        }
        return Ok((profile, ResponsesAuth::XaiBearer));
    }
    if profile_id.starts_with("gocode-responses/azure-openai-responses/") {
        let resource = settings
            .responses_resource
            .as_deref()
            .ok_or("Azure resource is required")?;
        let deployment = settings
            .responses_deployment
            .as_deref()
            .ok_or("Azure deployment is required")?;
        let model = profile_id
            .strip_prefix("gocode-responses/azure-openai-responses/")
            .and_then(|value| value.strip_suffix("/1"))
            .filter(|value| !value.is_empty())
            .ok_or("invalid Azure Responses profile")?;
        let accounting = azure_accounting(settings)?;
        let max_output = settings
            .responses_max_output_tokens
            .ok_or("Azure model output bound is required")?;
        let context = settings
            .responses_context_tokens
            .ok_or("Azure model context bound is required")?;
        if context <= max_output || context > 2_000_000 {
            return Err("Azure model bounds are invalid");
        }
        let input_bytes = usize::try_from(context - max_output)
            .ok()
            .and_then(|tokens| tokens.checked_mul(2))
            .ok_or("Azure model context is too large")?
            .min(2 * 1024 * 1024);
        let profile = azure_profile(
            resource,
            deployment,
            model,
            max_output,
            settings
                .responses_pricing_digest
                .ok_or("Azure pricing digest is required")?,
            accounting,
        )
        .map_err(|_| "Azure Responses profile is invalid")?;
        return Ok((
            profile.with_limits(64, 131_072, input_bytes, input_bytes + 64 * 1024),
            ResponsesAuth::AzureApiKey,
        ));
    }
    Err("Responses profile is not in the closed registry")
}

fn reject_unexpected_settings(settings: &ProviderActivationSettings) -> Result<(), &'static str> {
    if settings.responses_resource.is_some()
        || settings.responses_deployment.is_some()
        || settings.responses_pricing_digest.is_some()
        || settings.responses_input_micros_per_million.is_some()
        || settings.responses_output_micros_per_million.is_some()
        || settings.responses_cached_input_micros_per_million.is_some()
        || settings.responses_max_output_tokens.is_some()
        || settings.responses_context_tokens.is_some()
        || settings.accounting_mode.is_some()
    {
        return Err("static Responses profile does not accept override settings");
    }
    Ok(())
}

fn explicit_pricing(
    settings: &ProviderActivationSettings,
) -> Result<(u64, u64, u64), &'static str> {
    let rates = (
        settings
            .responses_input_micros_per_million
            .ok_or("input PAYG rate is required")?,
        settings
            .responses_output_micros_per_million
            .ok_or("output PAYG rate is required")?,
        settings
            .responses_cached_input_micros_per_million
            .unwrap_or(0),
    );
    if rates.0 == 0 || rates.1 == 0 {
        return Err("input and output PAYG rates must be positive");
    }
    Ok(rates)
}

fn azure_accounting(
    settings: &ProviderActivationSettings,
) -> Result<ResponsesAccounting, &'static str> {
    match settings.accounting_mode {
        Some(ProviderAccountingMode::Payg) => {
            let rates = explicit_pricing(settings)?;
            Ok(ResponsesAccounting::Payg {
                input_micros_per_million: rates.0,
                output_micros_per_million: rates.1,
                cached_input_micros_per_million: rates.2,
            })
        }
        None => Ok(ResponsesAccounting::ExternallyBilledUnpriced),
        Some(ProviderAccountingMode::Subscription | ProviderAccountingMode::TokenPlan) => {
            Err("Azure Responses does not support subscription quota accounting")
        }
    }
}
