use std::sync::Arc;

use runne_api::{RemoteEffectAvailabilityV1, RemoteEffectCapabilitiesV1, TaskRunHostError};
use runne_application::ports::TaskRunEffectsReadSnapshot;
use runne_application::provider::{
    HistoricalProviderModelResolver, ProviderRemoteCredentialProjection,
    ProviderRemoteFactAuthenticator, ProviderRemoteGrantProjection,
    ProviderUnknownTerminalFactAuthenticator,
};
use runne_runtime::TaskRunEffectsEnricher;
use runne_runtime::handle::RuntimeHandle;
use runne_store::store::StoreTransaction;

use crate::canonical_provider::DaemonCanonicalProviderService;

pub(super) struct ProviderTaskRunEffectsEnricher {
    service: Arc<DaemonCanonicalProviderService>,
}

impl ProviderTaskRunEffectsEnricher {
    pub(super) fn new(service: Arc<DaemonCanonicalProviderService>) -> Self {
        Self { service }
    }
}

pub(super) fn build_task_run_host(
    handle: RuntimeHandle,
    store: StoreTransaction,
    provider: Option<Arc<DaemonCanonicalProviderService>>,
) -> runne_runtime::RuntimeTaskRunHost<StoreTransaction> {
    let Some(provider) = provider else {
        return runne_runtime::RuntimeTaskRunHost::new(handle, store);
    };
    runne_runtime::RuntimeTaskRunHost::new(handle, store)
        .with_effects_enricher(Arc::new(ProviderTaskRunEffectsEnricher::new(provider)))
}

impl TaskRunEffectsEnricher for ProviderTaskRunEffectsEnricher {
    fn remote_fact_authenticator(&self) -> Option<Arc<dyn ProviderRemoteFactAuthenticator>> {
        Some(self.service.task_run_effects_authenticator())
    }

    fn unknown_terminal_fact_authenticator(
        &self,
    ) -> Option<Arc<dyn ProviderUnknownTerminalFactAuthenticator>> {
        Some(self.service.task_run_unknown_terminal_authenticator())
    }

    fn historical_model_resolver(&self) -> Option<Arc<dyn HistoricalProviderModelResolver>> {
        Some(Arc::new(
            crate::canonical_provider::CompiledHistoricalProviderModelResolver,
        ))
    }

    fn runtime_metadata(
        &self,
        snapshot: &TaskRunEffectsReadSnapshot,
    ) -> Result<Option<(RemoteEffectAvailabilityV1, RemoteEffectCapabilitiesV1)>, TaskRunHostError>
    {
        let Some(remote) = snapshot.remote.as_ref() else {
            return Ok(None);
        };
        let static_projection = self
            .service
            .task_run_effects_static_capabilities(&remote.binding);
        Ok(Some(runtime_projection(
            static_projection.matched_profile,
            remote.credential,
            remote.secondary_grant,
            static_projection.capabilities,
        )))
    }
}

fn runtime_projection(
    matched_profile: bool,
    credential: ProviderRemoteCredentialProjection,
    grant: ProviderRemoteGrantProjection,
    capabilities: RemoteEffectCapabilitiesV1,
) -> (RemoteEffectAvailabilityV1, RemoteEffectCapabilitiesV1) {
    (
        runtime_availability(matched_profile, credential, grant),
        capabilities,
    )
}

fn runtime_availability(
    matched_profile: bool,
    credential: ProviderRemoteCredentialProjection,
    grant: ProviderRemoteGrantProjection,
) -> RemoteEffectAvailabilityV1 {
    if !matched_profile {
        return RemoteEffectAvailabilityV1::Unavailable;
    }
    let credential_ready = credential == ProviderRemoteCredentialProjection::Ready;
    let grant_active = matches!(
        grant,
        ProviderRemoteGrantProjection::NotSecondary | ProviderRemoteGrantProjection::Active { .. }
    );
    if credential_ready && grant_active {
        RemoteEffectAvailabilityV1::Available
    } else {
        RemoteEffectAvailabilityV1::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_secondary_grant_keeps_static_capabilities_but_closes_availability() {
        let caps = RemoteEffectCapabilitiesV1 {
            status_check: true,
            stream_resume: false,
            remote_cancel: true,
        };
        let (availability, projected_caps) = runtime_projection(
            true,
            ProviderRemoteCredentialProjection::Ready,
            ProviderRemoteGrantProjection::Revoked {
                authority_revision: 9,
            },
            caps,
        );
        assert_eq!(availability, RemoteEffectAvailabilityV1::Unavailable);
        assert!(projected_caps.status_check);
        assert!(projected_caps.remote_cancel);
        assert!(!projected_caps.stream_resume);
    }

    #[test]
    fn missing_exact_adapter_pin_closes_availability() {
        let availability = runtime_availability(
            false,
            ProviderRemoteCredentialProjection::Ready,
            ProviderRemoteGrantProjection::NotSecondary,
        );
        assert_eq!(availability, RemoteEffectAvailabilityV1::Unavailable);
    }
}
