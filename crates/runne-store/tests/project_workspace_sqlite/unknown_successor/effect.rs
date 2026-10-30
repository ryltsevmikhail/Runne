use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderFuture, ProviderPort, ProviderRecoveryAttemptIdentity,
    ProviderRecoveryBinding, ProviderResponseIdentityCommitter, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, RemoteResponseId,
    StreamCursor, StreamError,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    SqliteProviderExecutionStore,
};
use std::sync::Arc;

pub(super) struct Adapter;
pub(super) struct Ready(DispatchRequest);
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

impl ProviderPort for Adapter {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { unreachable!() })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }
}

pub(super) struct PersistRequestThenMaybeDispatch(pub Arc<SqliteProviderExecutionStore>);
impl ProviderEffectPort for PersistRequestThenMaybeDispatch {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let execution = Arc::clone(&self.0);
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::AttemptConflict)?;
            persist_request(&execution, &ready.0, "fixture-profile-v1").await?;
            Err(DispatchError::MaybeDispatched)
        })
    }
}

pub(super) struct PersistRequestThenMaybeDispatchWithRemoteId {
    pub execution: Arc<SqliteProviderExecutionStore>,
    pub response_id: String,
    pub profile_id: &'static str,
}
impl ProviderEffectPort for PersistRequestThenMaybeDispatchWithRemoteId {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Ready(request)) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let execution = Arc::clone(&self.execution);
        let response_id = self.response_id.clone();
        let profile_id = self.profile_id;
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::AttemptConflict)?;
            persist_request(&execution, &ready.0, profile_id).await?;
            persist_response_id(&execution, &ready.0, &response_id, profile_id).await?;
            Err(DispatchError::MaybeDispatched)
        })
    }
}

async fn persist_request(
    execution: &Arc<SqliteProviderExecutionStore>,
    request: &DispatchRequest,
    profile_id: &str,
) -> Result<(), DispatchError> {
    let provider = runne_provider::ProviderId::new("fixture-provider")
        .map_err(|_| DispatchError::AttemptConflict)?;
    let binding = execution
        .resolve_remote_attempt_binding(request.claim(), &provider, &provider, profile_id)
        .map_err(|_| DispatchError::AttemptConflict)?;
    if let Some(saved) = execution
        .load_remote_attempt(binding.dispatch_attempt_id)
        .map_err(|_| DispatchError::AttemptConflict)?
    {
        return if saved.request.binding == binding {
            Ok(())
        } else {
            Err(DispatchError::AttemptConflict)
        };
    }
    let identity = ProviderRecoveryAttemptIdentity::new(
        provider,
        runne_provider::ProviderId::new(&binding.credential_realm)
            .map_err(|_| DispatchError::AttemptConflict)?,
        binding.profile_id.clone(),
        binding.profile_digest,
        binding.semantic_digest,
        binding.prepared_digest,
        binding.pricing_digest,
        binding.request_digest,
        binding.runtime_authority_id,
        binding.database_generation,
        binding.runtime_generation,
        binding.fencing_token,
    )
    .map_err(|_| DispatchError::AttemptConflict)?;
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .map_err(|_| DispatchError::AttemptConflict)?;
    let committer =
        RuntimeProviderRemoteIdentityCommitter::new(Arc::new(Keyring), Arc::clone(execution));
    runne_provider::ProviderResponseIdentityCommitter::persist_request(
        &committer,
        recovery,
        &identity,
        request.prepared().rendered_bytes(),
    )
    .await
    .map_err(|_| DispatchError::AttemptConflict)
}

async fn persist_response_id(
    execution: &Arc<SqliteProviderExecutionStore>,
    request: &DispatchRequest,
    response_id: &str,
    profile_id: &str,
) -> Result<(), DispatchError> {
    let provider = runne_provider::ProviderId::new("fixture-provider")
        .map_err(|_| DispatchError::AttemptConflict)?;
    let binding = execution
        .resolve_remote_attempt_binding(request.claim(), &provider, &provider, profile_id)
        .map_err(|_| DispatchError::AttemptConflict)?;
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .map_err(|_| DispatchError::AttemptConflict)?;
    let committer =
        RuntimeProviderRemoteIdentityCommitter::new(Arc::new(Keyring), Arc::clone(execution));
    let response_id =
        RemoteResponseId::new(response_id).map_err(|_| DispatchError::AttemptConflict)?;
    ProviderResponseIdentityCommitter::commit(&committer, recovery, &response_id)
        .await
        .map_err(|_| DispatchError::AttemptConflict)
}

pub(super) struct Keyring;
impl ProviderJournalKeyring for Keyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }
    fn store_provider_journal_key(
        &self,
        _: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }
    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        ProviderJournalKeyMaterial::new(key, [7; 32])
    }
    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }
    fn provider_journal_key_status(
        &self,
        _: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(ProviderJournalKeyStatus::Available)
    }
}
