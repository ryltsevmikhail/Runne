use runne_provider::{ProviderCredentialEnrollmentStore, ProviderId};
use std::sync::Arc;

use super::super::composition::DaemonCanonicalProviderService;
use super::from_safe_snapshot;
use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;

impl DaemonCanonicalProviderService {
    /// Returns a fresh fail-closed readiness projection for the selected provider.
    pub(crate) fn current_provider_readiness(&self) -> runne_api::ProviderActivationReadinessV1 {
        let Some(reader) = self.credential_readback.as_deref() else {
            return match self.credential_status {
                runne_secure_store::ProviderCredentialStatus::Configured => {
                    runne_api::ProviderActivationReadinessV1::Ready
                }
                runne_secure_store::ProviderCredentialStatus::Missing => {
                    runne_api::ProviderActivationReadinessV1::CredentialMissing
                }
                runne_secure_store::ProviderCredentialStatus::Unsupported => {
                    runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable
                }
            };
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

    #[cfg(test)]
    pub(crate) fn current_secondary_provider_readiness(
        &self,
    ) -> Option<runne_api::ProviderActivationReadinessV1> {
        let route = self.secondary_profile.as_ref()?;
        let Some(reader) = route.credential_readback.as_deref() else {
            return Some(match route.credential_status {
                runne_secure_store::ProviderCredentialStatus::Configured => {
                    runne_api::ProviderActivationReadinessV1::Ready
                }
                runne_secure_store::ProviderCredentialStatus::Missing => {
                    runne_api::ProviderActivationReadinessV1::CredentialMissing
                }
                runne_secure_store::ProviderCredentialStatus::Unsupported => {
                    runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable
                }
            });
        };
        let provider = ProviderId::new(route.provider_id.as_ref()).ok()?;
        if route
            .credential_store
            .begin_admission_snapshot(&provider)
            .is_err()
            || CredentialEnrollmentRecoveryGateway::new(route.credential_store.as_ref(), reader)
                .reconcile_online(chrono::Utc::now().timestamp())
                .is_err()
        {
            return Some(runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable);
        }
        Some(
            route
                .credential_store
                .safe_snapshot(&provider)
                .map(|snapshot| from_safe_snapshot(&snapshot))
                .unwrap_or(runne_api::ProviderActivationReadinessV1::SecureStoreUnavailable),
        )
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
