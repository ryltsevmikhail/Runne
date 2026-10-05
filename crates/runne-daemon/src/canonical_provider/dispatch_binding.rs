use core::any::Any;
use std::sync::Arc;

use runne_application::ports::{
    BindPreparedTaskRunProviderRoundEffect, PreparedTaskRunProviderRequest,
    TaskRunAssignmentIdentity, TaskRunProviderBindingPort,
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
    taskrun_round: Option<(TaskRunAssignmentIdentity, u64, D2ProviderRound, [u8; 32])>,
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
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    continuation_target_fence: Option<
        crate::application::exec_taskrun_worker::tool_invocation::target_snapshot::D2TargetFence,
    >,
}

struct ProviderRequestIntent {
    claim: ProviderDispatchClaim,
    prepared: PreparedRequest,
}

#[derive(Clone)]
enum TaskRunPreparedBinding {
    Legacy(runne_application::ports::BindPreparedTaskRunProviderEffect),
    ToolRound(BindPreparedTaskRunProviderRoundEffect),
}

use super::execution::D2ProviderRound;

pub(super) struct OnlineDispatchFenceConfig<'a> {
    pub(super) authority: CredentialDispatchAuthority<'a>,
    pub(super) inner: &'a dyn ProviderEffectPort,
    pub(super) trust: Option<(
        crate::application::trust_delivery::DeliveryTrustGate,
        String,
        runne_domain::id::ConversationId,
    )>,
    pub(super) taskrun: Option<(TaskRunAssignmentIdentity, u64, [u8; 32])>,
    pub(super) taskrun_round: Option<(TaskRunAssignmentIdentity, u64, D2ProviderRound, [u8; 32])>,
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
            taskrun_round: config.taskrun_round,
            taskrun_store: config.taskrun_store,
            request_intents: config.request_intents,
            provider_id: config.provider_id,
            credential_realm: config.credential_realm,
            profile_id: config.profile_id,
        }
    }
}

mod port;

fn bind_taskrun_request(
    store: &StoreTransaction,
    binding: &TaskRunPreparedBinding,
    recheck: bool,
) -> Result<(), runne_application::ports::TaskRunProviderBindingError> {
    match binding {
        TaskRunPreparedBinding::Legacy(request) => store
            .bind_prepared_taskrun_provider_effect(request.clone())
            .map(|_| ()),
        TaskRunPreparedBinding::ToolRound(request) if recheck => {
            store.verify_prepared_taskrun_provider_round_effect(request.clone())
        }
        TaskRunPreparedBinding::ToolRound(request) => store
            .bind_prepared_taskrun_provider_round_effect(request.clone())
            .map(|_| ()),
    }
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
