use core::any::Any;
use std::sync::Arc;

use runne_application::ports::{
    PreparedTaskRunProviderRequest, TaskRunAssignmentIdentity, TaskRunProviderBindingPort,
};
use runne_provider::{
    DispatchError, DispatchRequest, PreparedRequest, ProviderDispatchClaim, ProviderFuture,
    ProviderId, ProviderPreEffectRejection, ProviderRecoveryDispatchContextProvider,
    ProviderStreamId,
};
use runne_store::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect,
};
use runne_store::store::StoreTransaction;

/// Revalidates the sealed store-owned online binding at the daemon's native
/// materialization boundary without exposing its durable tuple.
pub(super) struct OnlineDispatchFence<'a> {
    authority: CredentialDispatchAuthority<'a>,
    inner: &'a dyn ProviderEffectPort,
    trust: Option<ProviderTrustContext>,
    taskrun: Option<(TaskRunAssignmentIdentity, u64, [u8; 32])>,
    taskrun_store: &'a StoreTransaction,
    request_intents: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    provider_id: ProviderId,
    credential_realm: ProviderId,
    profile_id: String,
}

struct ProviderTrustContext {
    gate: crate::application::trust_delivery::DeliveryTrustGate,
    principal: String,
    conversation_id: runne_domain::id::ConversationId,
}

struct LeasedReadyEffect {
    ready: Box<dyn ProviderReadyEffect>,
    lease: Option<Box<dyn runne_application::project_trust::ProjectTrustEffectLease>>,
    taskrun_binding: Option<TaskRunPreparedBinding>,
    intent: ProviderRequestIntent,
}

struct ProviderRequestIntent {
    claim: ProviderDispatchClaim,
    prepared: PreparedRequest,
}

#[derive(Clone)]
struct TaskRunPreparedBinding {
    identity: TaskRunAssignmentIdentity,
    expected_claim_version: u64,
    prepared: PreparedTaskRunProviderRequest,
}

pub(super) struct OnlineDispatchFenceConfig<'a> {
    pub(super) authority: CredentialDispatchAuthority<'a>,
    pub(super) inner: &'a dyn ProviderEffectPort,
    pub(super) trust: Option<(
        crate::application::trust_delivery::DeliveryTrustGate,
        String,
        runne_domain::id::ConversationId,
    )>,
    pub(super) taskrun: Option<(TaskRunAssignmentIdentity, u64, [u8; 32])>,
    pub(super) taskrun_store: &'a StoreTransaction,
    pub(super) request_intents: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    pub(super) provider_id: ProviderId,
    pub(super) credential_realm: ProviderId,
    pub(super) profile_id: String,
}

impl ProviderReadyEffect for LeasedReadyEffect {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl<'a> OnlineDispatchFence<'a> {
    pub(super) fn new(config: OnlineDispatchFenceConfig<'a>) -> Self {
        Self {
            authority: config.authority,
            inner: config.inner,
            trust: config
                .trust
                .map(|(gate, principal, conversation_id)| ProviderTrustContext {
                    gate,
                    principal,
                    conversation_id,
                }),
            taskrun: config.taskrun,
            taskrun_store: config.taskrun_store,
            request_intents: config.request_intents,
            provider_id: config.provider_id,
            credential_realm: config.credential_realm,
            profile_id: config.profile_id,
        }
    }
}

impl ProviderEffectPort for OnlineDispatchFence<'_> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            if credential
                .validate_online_materialization(
                    self.authority,
                    request.claim(),
                    chrono::Utc::now().timestamp(),
                )
                .is_err()
            {
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ));
            }
            let intent = ProviderRequestIntent {
                claim: request.claim().clone(),
                prepared: request.prepared().clone(),
            };
            let taskrun_binding = if let Some((identity, expected_claim_version, profile_digest)) =
                &self.taskrun
            {
                let prepared = request.prepared();
                let binding = TaskRunPreparedBinding {
                    identity: identity.clone(),
                    expected_claim_version: *expected_claim_version,
                    prepared: PreparedTaskRunProviderRequest {
                        call_id: prepared.call().call_id(),
                        call_digest_version: prepared.request_ref().digest_version(),
                        prepared_digest: *prepared.request_ref().as_bytes(),
                        render_digest: *prepared.render_digest(),
                        profile_digest: *profile_digest,
                        provider_idempotency_key: request.provider_idempotency_key().into(),
                    },
                };
                bind_taskrun_request(self.taskrun_store, &binding).map_err(|_error| {
                    DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
                })?;
                Some(binding)
            } else {
                None
            };
            let ready = self.inner.stage_effect(request, credential).await?;
            wait_for_t1_test_barrier("stage-ready").await?;
            let lease = match &self.trust {
                Some(context) => context
                    .gate
                    .acquire_provider_effect_lease(&context.principal, context.conversation_id)
                    .map_err(|_| {
                        DispatchError::RejectedBeforeEffect(
                            ProviderPreEffectRejection::AdapterRejected,
                        )
                    })?,
                None => None,
            };
            if lease.is_some() {
                wait_for_t1_test_barrier("lease-held").await?;
            }
            Ok(Box::new(LeasedReadyEffect {
                ready,
                lease,
                taskrun_binding,
                intent,
            }) as Box<dyn ProviderReadyEffect>)
        })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let ready = ready.into_any();
        let Ok(ready) = ready.downcast::<LeasedReadyEffect>() else {
            return Box::pin(async { Err(DispatchError::MaybeDispatched) });
        };
        let LeasedReadyEffect {
            ready,
            lease,
            taskrun_binding,
            intent,
        } = *ready;
        if let Some(binding) = &taskrun_binding
            && bind_taskrun_request(self.taskrun_store, binding).is_err()
        {
            return Box::pin(async {
                Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ))
            });
        }
        if !receipt.matches_claim(&intent.claim) {
            return Box::pin(async { Err(DispatchError::MaybeDispatched) });
        }
        let request_intents = Arc::clone(&self.request_intents);
        let provider_id = self.provider_id.clone();
        let credential_realm = self.credential_realm.clone();
        let profile_id = self.profile_id.clone();
        let taskrun_store = self.taskrun_store;
        let inner = self.inner;
        Box::pin(async move {
            let context = request_intents
                .for_new_dispatch(&intent.claim, &provider_id, &credential_realm, &profile_id)
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            context
                .persist_request(intent.prepared.rendered_bytes())
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            // Intent persistence can yield while a caller accepts cancellation.
            // Recheck at the last wrapper-controlled point before the adapter
            // begins materialization or transport. A stale receipt remains an
            // audit fact, but cannot authorize a fresh adapter dispatch.
            if let Some(binding) = &taskrun_binding
                && bind_taskrun_request(taskrun_store, binding).is_err()
            {
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ));
            }
            // Keep project trust held through adapter materialization and
            // transport. The final TaskRun recheck above is the gate's
            // linearization point; a cancellation committed after it is an
            // already-started uncertain outcome, never a second dispatch.
            let outcome = inner.dispatch_effect(ready, receipt).await;
            drop(lease);
            outcome
        })
    }
}

fn bind_taskrun_request(
    store: &StoreTransaction,
    binding: &TaskRunPreparedBinding,
) -> Result<(), runne_application::ports::TaskRunProviderBindingError> {
    store
        .bind_prepared_taskrun_provider_effect(
            runne_application::ports::BindPreparedTaskRunProviderEffect {
                identity: binding.identity.clone(),
                expected_claim_version: binding.expected_claim_version,
                prepared: binding.prepared.clone(),
            },
        )
        .map(|_| ())
}

async fn wait_for_t1_test_barrier(stage: &str) -> Result<(), DispatchError> {
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    {
        use std::time::{Duration, Instant};
        if std::env::var("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref() == Ok("1")
            && let Some(root) = std::env::var_os("RUNNE_TEST_T1_TRUST_BARRIER_DIR")
        {
            let root = std::path::PathBuf::from(root);
            std::fs::write(root.join(format!("{stage}.entered")), b"ready").map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while !root.join(format!("{stage}.release")).exists() {
                if Instant::now() >= deadline {
                    return Err(DispatchError::RejectedBeforeEffect(
                        ProviderPreEffectRejection::AdapterRejected,
                    ));
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    let _ = stage;
    Ok(())
}
