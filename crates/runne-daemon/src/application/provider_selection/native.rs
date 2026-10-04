use super::SelectedProviderRuntime;
use crate::canonical_provider::{SharedTextProviderProfile, native_effect_adapter};
use crate::error::DaemonError;
use crate::provider_activation::ProviderAccountingMode;
use crate::provider_activation::ProviderActivation;
use runne_daemon_native_effect::{NativeAuthDescriptor, TrustedNativeEndpoint};
use runne_provider_native_wire::{
    AnthropicMessagesProfile, GeminiProfile, NativeAccounting, NativeWireProfile, WireLimits,
};
use runne_provider_quota::QuotaStateStore;
use runne_secure_store::ProviderCredentialId;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::borrow::Cow;
use std::sync::Arc;

#[path = "native_registry.rs"]
mod native_registry;
use native_registry::{Spec, WireKind, full_profile_digest, pricing_digest, spec};

pub(super) const REVISION: &str = "pi-0.85.1";

pub(super) fn credential_id(
    binding: &runne_api::ProviderActivationBindingV1,
) -> Option<ProviderCredentialId> {
    spec(binding.profile_id()).map(|item| ProviderCredentialId::Generic(item.provider_id))
}

pub(super) fn runtime(
    activation: &ProviderActivation,
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let ProviderActivation::NativeText(binding, settings) = activation else {
        return Err(DaemonError::Config("native activation expected".into()));
    };
    ProviderActivation::validate_settings(binding.mode(), binding.profile_id(), settings)
        .map_err(|message| DaemonError::Config(message.into()))?;
    let spec = spec(binding.profile_id()).ok_or_else(|| {
        DaemonError::Config("native provider profile is not in the trusted registry".into())
    })?;
    let (profile, endpoint, auth) = build_profile(spec, binding, settings)?;
    let profile_for_factory = profile.clone();
    let endpoint_for_factory = endpoint.clone();
    let provider_id = spec.provider_id;
    let model_id = spec.model_id;
    let model_revision = REVISION;
    let scope = "provider.native.text";
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(
            move |authority, budget_store: Arc<SqliteProviderCredentialLifecycleStore>| {
                runne_daemon_native_effect::NativeEffect::new_with_quota_and_budget(
                    profile_for_factory.clone(),
                    endpoint_for_factory.clone(),
                    auth,
                    authority,
                    Default::default(),
                    Some(quota_store.clone()),
                    Some(budget_store),
                )
                .map(native_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("native provider adapter unavailable".into()))
            },
        ),
        provider_id: Cow::Borrowed(provider_id),
        model_id: Cow::Borrowed(model_id),
        model_revision: Cow::Borrowed(model_revision),
        scope: Cow::Borrowed(scope),
        credential_id: ProviderCredentialId::Generic(provider_id),
    })
}

fn build_profile(
    spec: Spec,
    binding: &runne_api::ProviderActivationBindingV1,
    settings: &crate::provider_activation::ProviderActivationSettings,
) -> Result<
    (
        NativeWireProfile,
        TrustedNativeEndpoint,
        NativeAuthDescriptor,
    ),
    DaemonError,
> {
    let endpoint = match spec.kind {
        WireKind::Vertex => {
            let project = settings
                .vertex_project
                .as_deref()
                .ok_or_else(|| DaemonError::Config("Vertex project is required".into()))?;
            let location = settings
                .vertex_location
                .as_deref()
                .ok_or_else(|| DaemonError::Config("Vertex location is required".into()))?;
            TrustedNativeEndpoint::vertex(
                format!("https://{location}-aiplatform.googleapis.com"),
                project,
                location,
            )
        }
        WireKind::Anthropic => TrustedNativeEndpoint::anthropic(spec.endpoint.to_owned()),
        WireKind::Gemini => TrustedNativeEndpoint::gemini(spec.endpoint.to_owned()),
    }
    .map_err(|_| DaemonError::Config("native endpoint is not trusted".into()))?;
    let endpoint_text = match &endpoint {
        TrustedNativeEndpoint::Anthropic { base_url }
        | TrustedNativeEndpoint::Gemini { base_url } => base_url.as_str(),
        TrustedNativeEndpoint::Vertex {
            base_url,
            project,
            location,
        } => {
            return build_vertex_profile(
                spec,
                binding,
                settings,
                endpoint.clone(),
                format!("{base_url}|project:{project}|location:{location}"),
            );
        }
    };
    let accounting = accounting(spec, settings)?;
    let max_input_tokens = spec
        .context_window
        .checked_sub(u64::from(spec.max_output_tokens))
        .ok_or_else(|| DaemonError::Config("native model context is too small".into()))?;
    let max_input_bytes = usize::try_from(max_input_tokens)
        .ok()
        .and_then(|tokens| tokens.checked_mul(2))
        .map_or(2 * 1024 * 1024, |bytes| bytes.min(2 * 1024 * 1024));
    let limits = WireLimits::new_with_input_tokens(
        64,
        262_144,
        max_input_bytes,
        max_input_tokens,
        spec.max_output_tokens,
        8 * 1024 * 1024,
        65_536,
    )
    .map_err(|_| DaemonError::Config("native provider limits are invalid".into()))?;
    if !limits.fits_context(spec.context_window) {
        return Err(DaemonError::Config(
            "native limits exceed model context".into(),
        ));
    }
    let profile_digest = full_profile_digest(spec, endpoint_text, accounting, limits);
    if accounting == spec.accounting && profile_digest != spec.profile_digest {
        return Err(DaemonError::Config(
            "native profile registry digest mismatch".into(),
        ));
    }
    if binding.profile_digest() != &profile_digest {
        return Err(DaemonError::Config("native profile digest mismatch".into()));
    }
    let pricing_digest = pricing_digest(spec.provider_id, spec.model_id, accounting);
    if accounting == spec.accounting && pricing_digest != spec.pricing_digest {
        return Err(DaemonError::Config("native pricing digest mismatch".into()));
    }
    let profile = match spec.kind {
        WireKind::Anthropic => NativeWireProfile::Anthropic(
            AnthropicMessagesProfile::new_with_accounting(
                spec.provider_id,
                spec.profile_id,
                spec.model_id,
                REVISION,
                profile_digest,
                pricing_digest,
                limits,
                accounting,
            )
            .map_err(|_| DaemonError::Config("native profile construction failed".into()))?,
        ),
        WireKind::Gemini | WireKind::Vertex => NativeWireProfile::Gemini(
            GeminiProfile::new_with_accounting(
                spec.provider_id,
                spec.profile_id,
                spec.model_id,
                REVISION,
                profile_digest,
                pricing_digest,
                limits,
                accounting,
            )
            .map_err(|_| DaemonError::Config("native profile construction failed".into()))?,
        ),
    };
    Ok((profile, endpoint, spec.auth))
}

#[cfg(test)]
pub(super) fn profile_for_fixture(
    binding: &runne_api::ProviderActivationBindingV1,
) -> Result<
    (
        NativeWireProfile,
        TrustedNativeEndpoint,
        NativeAuthDescriptor,
    ),
    DaemonError,
> {
    let spec = spec(binding.profile_id()).ok_or_else(|| {
        DaemonError::Config("native provider profile is not in the trusted registry".into())
    })?;
    build_profile(
        spec,
        binding,
        &crate::provider_activation::ProviderActivationSettings::default(),
    )
}

fn build_vertex_profile(
    spec: Spec,
    binding: &runne_api::ProviderActivationBindingV1,
    settings: &crate::provider_activation::ProviderActivationSettings,
    endpoint: TrustedNativeEndpoint,
    endpoint_text: String,
) -> Result<
    (
        NativeWireProfile,
        TrustedNativeEndpoint,
        NativeAuthDescriptor,
    ),
    DaemonError,
> {
    let accounting = accounting(spec, settings)?;
    let max_input_tokens = spec
        .context_window
        .checked_sub(u64::from(spec.max_output_tokens))
        .ok_or_else(|| DaemonError::Config("native model context is too small".into()))?;
    let max_input_bytes = usize::try_from(max_input_tokens)
        .ok()
        .and_then(|tokens| tokens.checked_mul(2))
        .map_or(2 * 1024 * 1024, |bytes| bytes.min(2 * 1024 * 1024));
    let limits = WireLimits::new_with_input_tokens(
        64,
        262_144,
        max_input_bytes,
        max_input_tokens,
        spec.max_output_tokens,
        8 * 1024 * 1024,
        65_536,
    )
    .map_err(|_| DaemonError::Config("native provider limits are invalid".into()))?;
    let profile_digest = full_profile_digest(spec, &endpoint_text, accounting, limits);
    if binding.profile_digest() != &profile_digest {
        return Err(DaemonError::Config("native profile digest mismatch".into()));
    }
    let pricing = pricing_digest(spec.provider_id, spec.model_id, accounting);
    let profile = NativeWireProfile::Gemini(
        GeminiProfile::new_with_accounting(
            spec.provider_id,
            spec.profile_id,
            spec.model_id,
            REVISION,
            profile_digest,
            pricing,
            limits,
            accounting,
        )
        .map_err(|_| DaemonError::Config("native profile construction failed".into()))?,
    );
    Ok((profile, endpoint, spec.auth))
}

fn accounting(
    spec: Spec,
    settings: &crate::provider_activation::ProviderActivationSettings,
) -> Result<NativeAccounting, DaemonError> {
    let minimax = spec.provider_id == "minimax" || spec.provider_id == "minimax-cn";
    match (minimax, settings.accounting_mode) {
        (true, Some(ProviderAccountingMode::Payg)) => Ok(spec.accounting),
        (true, Some(ProviderAccountingMode::TokenPlan)) => {
            Ok(NativeAccounting::TokenPlanQuotaExternallyMetered)
        }
        (true, _) => Err(DaemonError::Config(
            "MiniMax accounting mode must be explicit".into(),
        )),
        (false, None) => Ok(spec.accounting),
        (false, _) => Err(DaemonError::Config(
            "accounting mode is inappropriate for native provider".into(),
        )),
    }
}
