use super::*;
use runne_api::ProviderQuotaProjectionV1;

pub(super) fn runtime_profile(
    version: &'static str,
    provider_service: Option<Arc<DaemonCanonicalProviderService>>,
    provider_activation: &ProviderActivation,
    provider_readiness: runne_api::ProviderActivationReadinessV1,
    runtime_capabilities: &'static [&'static str],
) -> RuntimeProfileHttpState {
    let runtime_profile_state = RuntimeProfileHttpState::new(
        runne_runtime::bundle::BUNDLE_ID,
        runne_runtime::bundle::PUBLISHED_BUNDLE_HASH,
        version,
        runtime_capabilities,
    );
    let state = match provider_service.clone() {
        Some(service) => {
            let activation = provider_activation.clone();
            let status_service = service.clone();
            runtime_profile_state.with_dynamic_provider_statuses(Arc::new(move || {
                super::super::provider_status::with_coding_profile(
                    super::super::provider_status::provider_statuses(
                        &activation,
                        status_service.current_provider_readiness(),
                    ),
                    &status_service,
                )
            }))
        }
        None => runtime_profile_state.with_provider_statuses(
            super::super::provider_status::provider_statuses(
                provider_activation,
                provider_readiness,
            ),
        ),
    };
    let activation = provider_activation.clone();
    let quota_readiness = provider_readiness;
    let quota_service = provider_service.clone();
    let quota_store = provider_service
        .as_ref()
        .map(|service| service.quota_store());
    state.with_dynamic_provider_quota(Arc::new(move || {
        let statuses = super::super::provider_status::provider_statuses(
            &activation,
            quota_service.as_ref().map_or(quota_readiness, |service| {
                service.current_provider_readiness()
            }),
        );
        let version = quota_service
            .as_ref()
            .and_then(|service| service.current_provider_credential_version());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        statuses
            .into_iter()
            .filter(|status| status.selected())
            .map(|status| match quota_store.as_ref() {
                Some(store) => {
                    super::super::quota::projection(store, status.provider_id(), version, now)
                }
                None => ProviderQuotaProjectionV1::unknown(status.provider_id()),
            })
            .collect()
    }))
}
