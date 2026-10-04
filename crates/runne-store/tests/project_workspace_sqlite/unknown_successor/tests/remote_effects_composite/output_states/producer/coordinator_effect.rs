use crate::project_workspace_sqlite::unknown_successor::effect::Keyring;
use runne_provider::{
    DispatchError, DispatchRequest, ProviderFuture, ProviderRecoveryDispatchContextProvider,
    ProviderStreamId, RemoteResponseId,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
    SqliteProviderExecutionStore,
};
use std::sync::Arc;

struct Ready(DispatchRequest);

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

pub(super) struct PersistRequestAndStartStream {
    pub execution: Arc<SqliteProviderExecutionStore>,
    pub response_id: String,
}

impl ProviderEffectPort for PersistRequestAndStartStream {
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
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::AttemptConflict)?;
            let request = &ready.0;
            let provider = runne_provider::ProviderId::new("fixture-provider")
                .map_err(|_| DispatchError::AttemptConflict)?;
            let realm = runne_provider::ProviderId::new("fixture-provider")
                .map_err(|_| DispatchError::AttemptConflict)?;
            let committer =
                RuntimeProviderRemoteIdentityCommitter::new(Arc::new(Keyring), execution);
            let context = committer
                .for_new_dispatch(request.claim(), &provider, &realm, "fixture-profile-v1")
                .await
                .map_err(|_| DispatchError::AttemptConflict)?;
            context
                .persist_request(request.prepared().rendered_bytes())
                .await
                .map_err(|_| DispatchError::AttemptConflict)?;
            let response_id =
                RemoteResponseId::new(&response_id).map_err(|_| DispatchError::AttemptConflict)?;
            context
                .commit_response_id(&response_id)
                .await
                .map_err(|_| DispatchError::AttemptConflict)?;
            Ok(ProviderStreamId::from_bytes(
                *request.claim().attempt_id.as_bytes(),
            ))
        })
    }
}
