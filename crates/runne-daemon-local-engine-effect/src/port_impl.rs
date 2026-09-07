use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderStreamId, ProviderStreamItem, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};
use runne_store::provider::{ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect};

use crate::engine::{receipt_matches, rejected_before_effect};
use crate::{Sender, Staged};

impl ProviderPort for Sender {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        crate::prepare_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        crate::ensure_digest_version(version)?;
        self.prepare(call)
    }

    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        // Effects start only through the durable stage/receipt CAS.
        Box::pin(async { Err(rejected_before_effect()) })
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
        // A deterministic local effect that was claimed but whose
        // terminal evidence is absent is, by contract, uncertain.
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

impl ProviderEffectPort for Sender {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        _credential: runne_store::provider::CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move { Ok(Box::new(Staged { request }) as Box<dyn ProviderReadyEffect>) })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let ready = ready.into_any();
            let Ok(staged) = ready.downcast::<Staged>() else {
                return Err(DispatchError::MaybeDispatched);
            };
            if !receipt_matches(&receipt, &staged) {
                return Err(DispatchError::MaybeDispatched);
            }
            self.dispatch_staged(*staged, receipt)
        })
    }
}
