use super::*;
use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamError,
};

/// Daemon-local object type for adapters that own both prepare/stream and
/// durable effect-start authority.
pub(crate) trait CanonicalProviderEffect: ProviderPort + ProviderEffectPort {}

impl<T> CanonicalProviderEffect for T where T: ProviderPort + ProviderEffectPort {}

pub(crate) type ProviderEffectFactory = dyn Fn(
        gocode_provider::NativeCredentialAuthority,
    ) -> Result<Arc<dyn CanonicalProviderEffect>, DaemonError>
    + Send
    + Sync;

struct OpenAiAdapter {
    inner: Arc<dyn gocode_daemon_openai_effect::OpenAiEffect>,
}

struct DeepSeekAdapter {
    inner: Arc<dyn gocode_daemon_deepseek_effect::DeepSeekEffect>,
}

pub(crate) fn openai_effect_adapter(
    inner: Arc<dyn gocode_daemon_openai_effect::OpenAiEffect>,
) -> Arc<dyn CanonicalProviderEffect> {
    Arc::new(OpenAiAdapter { inner })
}

pub(crate) fn deepseek_effect_adapter(
    inner: Arc<dyn gocode_daemon_deepseek_effect::DeepSeekEffect>,
) -> Arc<dyn CanonicalProviderEffect> {
    Arc::new(DeepSeekAdapter { inner })
}

macro_rules! impl_provider_adapter {
    ($adapter:ty) => {
        impl ProviderPort for $adapter {
            fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
                self.inner.prepare(call)
            }

            fn prepare_for_digest_version(
                &self,
                call: &ProviderCall,
                version: gocode_provider::ProviderCallDigestVersion,
            ) -> Result<PreparedRequest, PrepareError> {
                self.inner.prepare_for_digest_version(call, version)
            }

            fn dispatch(
                &self,
                request: DispatchRequest,
            ) -> gocode_provider::ProviderFuture<'_, Result<ProviderStreamId, DispatchError>>
            {
                self.inner.dispatch(request)
            }

            fn next<'a>(
                &'a self,
                stream: &'a ProviderStreamId,
                cursor: StreamCursor,
            ) -> gocode_provider::ProviderFuture<'a, Result<ProviderStreamItem, StreamError>>
            {
                self.inner.next(stream, cursor)
            }

            fn cancel(
                &self,
                request: CancelRequest,
            ) -> gocode_provider::ProviderFuture<'_, Result<CancelDisposition, DispatchError>>
            {
                self.inner.cancel(request)
            }

            fn reconcile(
                &self,
                request: ReconcileRequest,
            ) -> gocode_provider::ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>>
            {
                self.inner.reconcile(request)
            }
        }

        impl ProviderEffectPort for $adapter {
            fn stage_effect(
                &self,
                request: DispatchRequest,
                credential: gocode_store::provider::CredentialDispatchBinding,
            ) -> gocode_provider::ProviderFuture<
                '_,
                Result<Box<dyn gocode_store::provider::ProviderReadyEffect>, DispatchError>,
            > {
                self.inner.stage_effect(request, credential)
            }

            fn dispatch_effect(
                &self,
                ready: Box<dyn gocode_store::provider::ProviderReadyEffect>,
                receipt: gocode_store::provider::ProviderEffectStartReceipt,
            ) -> gocode_provider::ProviderFuture<'_, Result<ProviderStreamId, DispatchError>>
            {
                self.inner.dispatch_effect(ready, receipt)
            }
        }
    };
}

impl_provider_adapter!(OpenAiAdapter);
impl_provider_adapter!(DeepSeekAdapter);
