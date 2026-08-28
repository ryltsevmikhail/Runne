use runne_api::{
    ProviderCredentialLastDispositionV2, ProviderCredentialPendingOperationV2,
    ProviderCredentialProviderV2, ProviderCredentialReadinessV2, ProviderCredentialSafeSnapshotV2,
    ProviderCredentialStateV2, ProviderCredentialVerificationStateV2,
};

/// AppCore-owned renderer-safe V2 credential status projection.
///
/// It deliberately copies the allowlisted fields instead of forwarding the
/// runtime DTO so future wire fields cannot silently become Tauri IPC fields.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCredentialEnrollmentProjection {
    provider_id: ProviderCredentialProviderV2,
    credential_state: ProviderCredentialStateV2,
    readiness: ProviderCredentialReadinessV2,
    lifecycle_revision: u64,
    readiness_revision: u64,
    observed_at: i64,
    verification_state: ProviderCredentialVerificationStateV2,
    verification_revision: u64,
    pending_operation: Option<ProviderCredentialPendingOperationV2>,
    cleanup_pending: bool,
    last_disposition: Option<ProviderCredentialLastDispositionV2>,
}

impl From<ProviderCredentialSafeSnapshotV2> for ProviderCredentialEnrollmentProjection {
    fn from(snapshot: ProviderCredentialSafeSnapshotV2) -> Self {
        Self {
            provider_id: snapshot.provider_id(),
            credential_state: snapshot.credential_state(),
            readiness: snapshot.readiness(),
            lifecycle_revision: snapshot.lifecycle_revision(),
            readiness_revision: snapshot.readiness_revision(),
            observed_at: snapshot.observed_at(),
            verification_state: snapshot.verification_state(),
            verification_revision: snapshot.verification_revision(),
            pending_operation: snapshot.pending_operation(),
            cleanup_pending: snapshot.cleanup_pending(),
            last_disposition: snapshot.last_disposition(),
        }
    }
}

impl AppCore {
    /// Refreshes one authoritative V2 status projection from the live runtime.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if the runtime is unavailable, incompatible,
    /// or changes identity while the status request is in flight.
    pub async fn provider_credential_enrollment_status(
        &self,
        provider: ProviderCredentialProviderV2,
    ) -> Result<ProviderCredentialEnrollmentProjection, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        let context = self.live_runtime_operation_context()?;
        let snapshot = context
            .client
            .provider_credential_status(provider)
            .await
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        self.require_current_operation_context(&context)?;
        Ok(snapshot.into())
    }
}
