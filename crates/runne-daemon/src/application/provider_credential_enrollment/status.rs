#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 host composes status after Task 11 owns trusted writer handoff"
    )
)]

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialProviderV2, ProviderCredentialSafeSnapshotV2,
};
use runne_provider::{ProviderCredentialEnrollmentStore, ProviderId};

use super::{
    CredentialEnrollmentReadback, CredentialEnrollmentRecoveryGateway, ProviderCredentialAdmission,
    effect_authority::map_store, projection,
};

/// Coordinates the authority-gated, recovery-first safe status projection.
pub(crate) struct ProviderCredentialEnrollmentStatus<'a, S: ?Sized, R: ?Sized> {
    admission: ProviderCredentialAdmission,
    store: &'a S,
    reader: &'a R,
}

impl<'a, S: ?Sized, R: ?Sized> ProviderCredentialEnrollmentStatus<'a, S, R> {
    /// Retains the paired admission verifier and metadata-only dependencies.
    pub(crate) const fn new(
        admission: ProviderCredentialAdmission,
        store: &'a S,
        reader: &'a R,
    ) -> Self {
        Self {
            admission,
            store,
            reader,
        }
    }
}

impl<S, R> ProviderCredentialEnrollmentStatus<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + ?Sized,
    R: CredentialEnrollmentReadback + ?Sized,
{
    /// Reconciles durable work before returning the current safe projection.
    pub(crate) fn load(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        provider: ProviderCredentialProviderV2,
        now_high_water: i64,
    ) -> Result<ProviderCredentialSafeSnapshotV2, ProviderCredentialEnrollmentHostError> {
        self.admission.require_base(authority)?;
        let provider = provider_id(provider)?;
        self.store
            .begin_admission_snapshot(&provider)
            .map_err(map_store)?;
        CredentialEnrollmentRecoveryGateway::new(self.store, self.reader)
            .reconcile_online(now_high_water)?;
        projection::safe_snapshot(self.store.safe_snapshot(&provider).map_err(map_store)?)
    }
}

fn provider_id(
    provider: ProviderCredentialProviderV2,
) -> Result<ProviderId, ProviderCredentialEnrollmentHostError> {
    ProviderId::new(provider.as_str())
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)
}
