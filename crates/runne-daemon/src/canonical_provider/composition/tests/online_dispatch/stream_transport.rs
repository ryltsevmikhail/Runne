use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_provider::*;
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};

pub(super) struct Ready;
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn core::any::Any + Send> {
        self
    }
}

pub(super) struct Transport<'a>(
    pub(super) Option<ProviderStreamId>,
    pub(super) std::sync::Mutex<Option<ProviderDispatchClaim>>,
    pub(super) std::sync::atomic::AtomicBool,
    pub(super) std::sync::Mutex<Option<CredentialDispatchBinding>>,
    pub(super) std::sync::Mutex<Option<ProviderEffectStartReceipt>>,
    pub(super) tokio::sync::Notify,
    pub(super) &'a dyn crate::canonical_provider::CanonicalProviderEffect,
);
impl ProviderEffectPort for Transport<'_> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        *self.1.lock().unwrap() = Some(request.claim().clone());
        *self.3.lock().unwrap() = Some(credential);
        Box::pin(async { Ok(Box::new(Ready) as Box<dyn ProviderReadyEffect>) })
    }
    fn dispatch_effect(
        &self,
        _: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        *self.4.lock().unwrap() = Some(receipt);
        self.5.notify_one();
        let stream = self.0;
        Box::pin(async move {
            assert!(
                !self.2.swap(true, std::sync::atomic::Ordering::SeqCst),
                "replay must not dispatch again"
            );
            match stream {
                Some(stream) => Ok(stream),
                None => std::future::pending().await,
            }
        })
    }
}
impl ProviderPort for Transport<'_> {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.6.prepare(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        self.6.prepare_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { panic!("legacy dispatch forbidden") })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        _: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async { panic!("fixture only opens a stream") })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { Ok(CancelDisposition::Requested) })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

pub(super) struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}
