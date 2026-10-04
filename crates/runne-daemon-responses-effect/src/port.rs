use crate::{Ready, Sender};
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderPreEffectRejection, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};

impl ProviderPort for Sender {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        prepare_call(&self.config.profile, call).map_err(|e| PrepareError::Render(e.to_string()))
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
            if events.is_empty() {
                streams.remove(stream);
                // The slot is released when the terminal event is consumed.
                drop(streams);
                return Err(StreamError::Closed);
            }
            let event = events.pop_front().ok_or(StreamError::Closed)?;
            let actual = event.sequence();
            if actual != cursor.sequence() {
                events.push_front(event);
                return Err(StreamError::SequenceGap {
                    expected: cursor.sequence(),
                    actual,
                });
            }
            let terminal = matches!(
                event.kind(),
                runne_provider::ProviderStreamEventKind::Finished { .. }
                    | runne_provider::ProviderStreamEventKind::ScannerCompleted { .. }
            );
            if terminal {
                streams.remove(stream);
                self.active_streams
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            drop(streams);
            ProviderStreamItem::from_event(event)
        })
    }
    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            let removed = self
                .streams
                .lock()
                .map_err(|_| DispatchError::MaybeDispatched)?
                .remove(&request.stream_id());
            if removed.is_some() {
                self.active_streams
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            Ok(CancelDisposition::Requested)
        })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

impl ProviderEffectPort for Sender {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            Ok(Box::new(Ready {
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
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::MaybeDispatched)?;
            let mut receipt = receipt;
            let final_send = receipt.take_final_send_authority().map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
            tokio::time::timeout_at(
                receipt.deadline().into(),
                self.execute(*ready, receipt, final_send),
            )
            .await
            .map_err(|_| DispatchError::MaybeDispatched)?
        })
    }
}

use runne_provider_responses_wire::prepare_call;
