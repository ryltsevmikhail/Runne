use runne_application::provider::{ProviderRemoteAttemptBinding, ProviderRemoteRecoveryStore};
use runne_provider::{
    ProviderFuture, ProviderRecoveryAuthorization, ProviderRecoveryControlAuthorizer,
    ProviderRecoveryError, ProviderRecoveryOperation, ProviderRecoveryRequest,
};
use runne_secure_store::{ProviderCredentialDispatchMaterializer, ProviderCredentialRecoveryRead};
use runne_store::provider::{SqliteProviderCredentialLifecycleStore, SqliteProviderExecutionStore};
use std::sync::Arc;

/// Current-head issuer for saved-ID OpenAI background recovery operations.
pub(crate) struct DaemonProviderRecoveryAuthorizer {
    credentials: Arc<SqliteProviderCredentialLifecycleStore>,
    execution: Arc<SqliteProviderExecutionStore>,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    blocking_gate: Arc<super::saved_remote_gate::SavedRemoteBlockingGate>,
}

impl DaemonProviderRecoveryAuthorizer {
    pub(crate) fn new(
        credentials: Arc<SqliteProviderCredentialLifecycleStore>,
        execution: Arc<SqliteProviderExecutionStore>,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        blocking_gate: Arc<super::saved_remote_gate::SavedRemoteBlockingGate>,
    ) -> Self {
        Self {
            credentials,
            execution,
            materializer,
            blocking_gate,
        }
    }

    fn authorize_blocking(
        &self,
        request: &ProviderRecoveryRequest,
        operation: ProviderRecoveryOperation,
    ) -> Result<ProviderRecoveryAuthorization, ProviderRecoveryError> {
        let identity = request
            .identity()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        let realm = identity.credential_realm().clone();
        if identity.provider_id().as_str() != "openai-background"
            || realm.as_str() != "openai-background"
            || identity.profile_id() != "gocode-openai-responses-background-text/1"
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let binding = ProviderRemoteAttemptBinding {
            taskrun_id: request.binding().task_run_id(),
            taskrun_attempt_id: request.binding().task_attempt_id(),
            dispatch_attempt_id: request.binding().provider_attempt_id(),
            provider_id: identity.provider_id().as_str().to_owned(),
            credential_realm: realm.as_str().to_owned(),
            profile_id: identity.profile_id().to_owned(),
            profile_digest: *identity.profile_digest(),
            pricing_digest: *identity.pricing_digest(),
            semantic_digest: *identity.semantic_digest(),
            prepared_digest: *identity.prepared_digest(),
            request_digest: *identity.request_digest(),
            runtime_authority_id: *identity.runtime_authority_id(),
            database_generation: identity.database_generation(),
            runtime_generation: identity.runtime_generation(),
            fencing_token: identity.fencing_token(),
        };
        let proof = self
            .execution
            .issue_remote_operation_proof(&binding, request.response_id(), operation)
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        self.execution
            .validate_remote_operation_proof(&proof, request.response_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let now = unix_seconds()?;
        let lease = self
            .credentials
            .active_lease(&realm)
            .map_err(|_| ProviderRecoveryError::Unavailable)?
            .ok_or(ProviderRecoveryError::Unavailable)?;
        let dispatch = self
            .credentials
            .authorize_dispatch(&lease, now)
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let lifecycle = runne_provider::ProviderCredentialEnrollmentStore::lifecycle_snapshot(
            self.credentials.as_ref(),
            &realm,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        if lifecycle.active_version() != Some(lease.version_ref())
            || dispatch.version_ref() != lease.version_ref()
        {
            return Err(ProviderRecoveryError::Unavailable);
        }
        let read = ProviderCredentialRecoveryRead::new(
            dispatch.native_capability(),
            lifecycle.lifecycle_revision(),
            lifecycle.fence(),
            &proof,
            &realm,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let material = self
            .materializer
            .materialize_recovery(read)
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let still_current = unix_seconds().and_then(|after| {
            self.credentials
                .validate_dispatch(&dispatch, after)
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
            let current = runne_provider::ProviderCredentialEnrollmentStore::lifecycle_snapshot(
                self.credentials.as_ref(),
                &realm,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
            if current.active_version() == Some(lease.version_ref())
                && current.lifecycle_revision() == lifecycle.lifecycle_revision()
                && current.fence() == lifecycle.fence()
            {
                Ok(())
            } else {
                Err(ProviderRecoveryError::Unavailable)
            }
        });
        still_current?;
        self.execution
            .validate_remote_operation_proof(&proof, request.response_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let (_, credential) = material.into_zeroizing();
        ProviderRecoveryAuthorization::new(credential, proof)
    }
}

impl ProviderRecoveryControlAuthorizer for DaemonProviderRecoveryAuthorizer {
    fn authorize_and_materialize<'a>(
        &'a self,
        request: &'a ProviderRecoveryRequest,
        operation: ProviderRecoveryOperation,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryAuthorization, ProviderRecoveryError>> {
        Box::pin(async move {
            let attempt = request.binding().provider_attempt_id();
            let Some(authorization_guard) = self.blocking_gate.retain_authorization(attempt) else {
                return Err(ProviderRecoveryError::Unavailable);
            };
            let Some(candidate_permit) = self.blocking_gate.reserve_candidate() else {
                return Err(ProviderRecoveryError::Unavailable);
            };
            let issuer = Self {
                credentials: Arc::clone(&self.credentials),
                execution: Arc::clone(&self.execution),
                materializer: Arc::clone(&self.materializer),
                blocking_gate: Arc::clone(&self.blocking_gate),
            };
            let request = request.clone();
            tokio::task::spawn_blocking(move || {
                let _authorization_guard = authorization_guard;
                let _candidate_permit = candidate_permit;
                issuer.authorize_blocking(&request, operation)
            })
            .await
            .map_err(|_| ProviderRecoveryError::Unavailable)?
        })
    }
}

fn unix_seconds() -> Result<i64, ProviderRecoveryError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .filter(|value| *value > 0)
        .ok_or(ProviderRecoveryError::Unavailable)
}
