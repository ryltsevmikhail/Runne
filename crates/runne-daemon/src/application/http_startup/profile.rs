use super::*;

pub(super) fn runtime_profile(
    provider_service: Option<Arc<DaemonCanonicalProviderService>>,
    provider_activation: &ProviderActivation,
    provider_readiness: runne_api::ProviderActivationReadinessV1,
    runtime_capabilities: &'static [&'static str],
) -> RuntimeProfileHttpState {
    let runtime_profile_state = RuntimeProfileHttpState::new(
        runne_runtime::bundle::BUNDLE_ID,
        runne_runtime::bundle::PUBLISHED_BUNDLE_HASH,
        env!("CARGO_PKG_VERSION"),
        runtime_capabilities,
    );
    match provider_service {
        Some(service) => {
            let activation = provider_activation.clone();
            runtime_profile_state.with_dynamic_provider_statuses(Arc::new(move || {
                super::super::provider_status::provider_statuses(
                    &activation,
                    service.current_provider_readiness(),
                )
            }))
        }
        None => runtime_profile_state.with_provider_statuses(
            super::super::provider_status::provider_statuses(
                &provider_activation,
                provider_readiness,
            ),
        ),
    }
}
