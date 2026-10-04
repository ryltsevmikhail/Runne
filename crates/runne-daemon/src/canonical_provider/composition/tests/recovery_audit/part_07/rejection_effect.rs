use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{
    ApplicationCommandContext, BindPreparedTaskRunProviderEffect, PreparedTaskRunProviderRequest,
    RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunProviderBindingPort,
};
use runne_application::service::TaskRunService;
use runne_domain::id::TaskRunId;
use runne_provider::{
    DispatchError, DispatchRequest, ProviderFuture, ProviderPreEffectRejection, ProviderStreamId,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use std::sync::{Arc, Mutex};

pub(super) struct StageCancellation {
    pub(super) taskrun_id: TaskRunId,
    pub(super) expected_version: u64,
    pub(super) context: ApplicationCommandContext,
    pub(super) authority: RuntimeAuthorityId,
    pub(super) result: Arc<Mutex<Option<u64>>>,
}

pub(super) struct RejectingEffect {
    pub(super) store: runne_store::store::StoreTransaction,
    pub(super) binding: Option<(TaskRunAssignmentIdentity, u64, [u8; 32])>,
    pub(super) cancellation: Option<StageCancellation>,
}

impl ProviderEffectPort for RejectingEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            if let Some((identity, version, profile_digest)) = &self.binding {
                let prepared = request.prepared();
                self.store
                    .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
                        identity: identity.clone(),
                        expected_claim_version: *version,
                        prepared: PreparedTaskRunProviderRequest {
                            call_id: prepared.call().call_id(),
                            call_digest_version: prepared.request_ref().digest_version(),
                            prepared_digest: *prepared.request_ref().as_bytes(),
                            render_digest: *prepared.render_digest(),
                            profile_digest: *profile_digest,
                            provider_idempotency_key: request.provider_idempotency_key().into(),
                        },
                    })
                    .map_err(|_| DispatchError::MaybeDispatched)?;
            }
            if let Some(cancellation) = &self.cancellation {
                let outcome = TaskRunService::new(
                    self.store.clone(),
                    self.store.clone(),
                    self.store.clone(),
                    cancellation.authority.clone(),
                )
                .cancel_task_run(
                    &cancellation.context,
                    CancelTaskRunInput {
                        taskrun_id: cancellation.taskrun_id,
                        expected_version: cancellation.expected_version,
                    },
                )
                .map_err(|_| DispatchError::MaybeDispatched)?;
                let runne_application::commands::CommandOutcome::TaskRunCancellationRequested {
                    new_version,
                    ..
                } = outcome
                else {
                    return Err(DispatchError::MaybeDispatched);
                };
                *cancellation
                    .result
                    .lock()
                    .map_err(|_| DispatchError::MaybeDispatched)? = Some(new_version);
            }
            Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            ))
        })
    }

    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        _: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("pre-effect rejection cannot dispatch") })
    }
}
