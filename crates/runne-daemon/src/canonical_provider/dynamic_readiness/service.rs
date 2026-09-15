use runne_provider::{ProviderCredentialEnrollmentStore, ProviderId};
use std::sync::Arc;

use super::super::composition::DaemonCanonicalProviderService;
use super::from_safe_snapshot;
use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;

impl DaemonCanonicalProviderService {
    /// Returns a fresh fail-closed readiness projection for the selected provider.
    pub(crate) fn current_provider_readiness(&self) -> runne_api::ProviderActivationReadinessV1 {
        let Some(reader) = self.credential_readback.as_deref() else {
            return runne_api::ProviderActivationReadinessV1::Ready;
        };
        let Ok(provider) = ProviderId::new(self.provider_id.as_ref()) else {
            return runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable;
        };
        if self
            .credential_store
            .begin_admission_snapshot(&provider)
            .is_err()
            || CredentialEnrollmentRecoveryGateway::new(self.credential_store.as_ref(), reader)
                .reconcile_online(chrono::Utc::now().timestamp())
                .is_err()
        {
            return runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable;
        }
        self.credential_store
            .safe_snapshot(&provider)
            .map(|snapshot| from_safe_snapshot(&snapshot))
            .unwrap_or(runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable)
    }

    /// Returns the durable active credential version for quota projection.
    pub(crate) fn current_provider_credential_version(&self) -> Option<u64> {
        let provider = ProviderId::new(self.provider_id.as_ref()).ok()?;
        self.credential_store
            .lifecycle_snapshot(&provider)
            .ok()?
            .active_version()
            .map(|version| version.version())
    }

    /// Returns the quota evidence store composed for this runtime instance.
    pub(crate) fn quota_store(&self) -> Arc<runne_provider_quota::QuotaStateStore> {
        Arc::clone(&self.quota_store)
    }
}
