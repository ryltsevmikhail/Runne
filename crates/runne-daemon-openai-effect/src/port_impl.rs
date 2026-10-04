use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderPreEffectRejection, ProviderRecoveryCapabilities, ProviderRecoveryError,
    ProviderRecoveryRequest, ProviderRemoteCheck, ProviderResumeRequest, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_provider_openai::{OpenAiCredentialError, OpenAiCredentialMaterializer};
use runne_store::provider::CredentialDispatchBinding;
use runne_store::provider::{ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect};

use crate::{Ready, Sender};

pub(crate) mod authorized;

use authorized::AuthorizedReady;

impl<C: OpenAiCredentialMaterializer> ProviderPort for Sender<C> {
    fn recovery_capabilities(&self) -> ProviderRecoveryCapabilities {
        self.recovery_capabilities
    }

    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.renderer
            .prepare(call)
            .map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        if version != ProviderCallDigestVersion::V2 {
            return Err(PrepareError::UnsupportedDigestVersion(version));
        }
        self.prepare(call)
    }

    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async {
            Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            ))
        })
    }

    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            let mut streams = self.streams.lock().map_err(|_| StreamError::NotFound)?;
            let events = streams.get_mut(stream).ok_or(StreamError::NotFound)?;
            let event = events.pop_front().ok_or(StreamError::Closed)?;
            if event.sequence() != cursor.sequence() {
                return Err(StreamError::SequenceGap {
                    expected: cursor.sequence(),
                    actual: event.sequence(),
                });
            }
            ProviderStreamItem::from_event(event)
        })
    }

    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            self.streams
                .lock()
                .map_err(|_| DispatchError::MaybeDispatched)?
                .remove(&request.stream_id());
            Ok(CancelDisposition::Requested)
        })
    }

    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }

    fn check_remote_status(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        Box::pin(crate::background::check_remote_status(self, request))
    }

    fn cancel_remote(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        Box::pin(crate::background::cancel_remote(self, request))
    }

    fn resume_remote_stream(
        &self,
        _: ProviderResumeRequest,
    ) -> ProviderFuture<'_, Result<Vec<runne_provider::ProviderStreamEvent>, ProviderRecoveryError>>
    {
        Box::pin(async { Err(ProviderRecoveryError::Unsupported) })
    }
}

impl<C: OpenAiCredentialMaterializer> ProviderEffectPort for Sender<C> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            Ok(Box::new(AuthorizedReady {
                request,
                credential,
            }) as Box<dyn ProviderReadyEffect>)
        })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let ready = ready.into_any();
            match ready.downcast::<AuthorizedReady>() {
                Ok(ready) => self.send_authorized(*ready, receipt).await,
                Err(ready) => match ready.downcast::<Ready>() {
                    Ok(ready) => self.send_ready(ready, receipt).await,
                    Err(_) => Err(DispatchError::MaybeDispatched),
                },
            }
        })
    }
}

pub(super) const fn map_credential(error: OpenAiCredentialError) -> DispatchError {
    DispatchError::RejectedBeforeEffect(match error {
        OpenAiCredentialError::Missing => ProviderPreEffectRejection::CredentialUnavailable,
        OpenAiCredentialError::AccessDenied => ProviderPreEffectRejection::CredentialAccessDenied,
    })
}
