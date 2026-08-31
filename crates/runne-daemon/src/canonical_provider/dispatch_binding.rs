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
}

impl<'a> OnlineDispatchFence<'a> {
    pub(super) const fn new(
        authority: CredentialDispatchAuthority<'a>,
        inner: &'a dyn ProviderEffectPort,
    ) -> Self {
        Self { authority, inner }
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
            self.inner.stage_effect(request, credential).await
        })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        self.inner.dispatch_effect(ready, receipt)
    }
}
