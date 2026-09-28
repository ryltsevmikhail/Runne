use core::any::Any;

use runne_provider::{
    DispatchError, DispatchRequest, ProviderFuture, ProviderPreEffectRejection, ProviderStreamId,
};
use runne_store::provider::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect,
};

/// Revalidates the sealed store-owned online binding at the daemon's native
/// materialization boundary without exposing its durable tuple.
pub(super) struct OnlineDispatchFence<'a> {
    authority: CredentialDispatchAuthority<'a>,
    inner: &'a dyn ProviderEffectPort,
    trust: Option<ProviderTrustContext>,
}

struct ProviderTrustContext {
    gate: crate::application::trust_delivery::DeliveryTrustGate,
    principal: String,
    conversation_id: runne_domain::id::ConversationId,
}

struct LeasedReadyEffect {
    ready: Box<dyn ProviderReadyEffect>,
    lease: Option<Box<dyn runne_application::project_trust::ProjectTrustEffectLease>>,
}

impl ProviderReadyEffect for LeasedReadyEffect {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl<'a> OnlineDispatchFence<'a> {
    pub(super) fn new(
        authority: CredentialDispatchAuthority<'a>,
        inner: &'a dyn ProviderEffectPort,
        trust: Option<(
            crate::application::trust_delivery::DeliveryTrustGate,
            String,
            runne_domain::id::ConversationId,
        )>,
    ) -> Self {
        Self {
            authority,
            inner,
            trust: trust.map(|(gate, principal, conversation_id)| ProviderTrustContext {
                gate,
                principal,
                conversation_id,
            }),
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
            Ok(Box::new(LeasedReadyEffect { ready, lease }) as Box<dyn ProviderReadyEffect>)
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
        let LeasedReadyEffect { ready, lease } = *ready;
        drop(lease);
        self.inner.dispatch_effect(ready, receipt)
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
