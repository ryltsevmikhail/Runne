use runne_provider::*;

pub(super) struct FailureProvider {
    pub(super) disposition: ProviderTerminalDisposition,
}
impl ProviderPort for FailureProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        let event = match cursor.sequence() {
            0 => ProviderStreamEventKind::Started,
            1 => ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(500, 900, 0, 0).unwrap(),
            },
            _ => ProviderStreamEventKind::Finished {
                disposition: self.disposition,
                reason: ProviderFinishReason::Error,
            },
        };
        Box::pin(async move {
            ProviderStreamItem::from_event(
                ProviderStreamEvent::new(cursor.sequence(), event).unwrap(),
            )
        })
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

pub(super) struct UnknownFailureProvider {
    pub(super) disposition: ProviderTerminalDisposition,
}

impl ProviderPort for UnknownFailureProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        let event = match cursor.sequence() {
            0 => ProviderStreamEventKind::Started,
            1 => ProviderStreamEventKind::UsageUnavailable,
            _ => ProviderStreamEventKind::Finished {
                disposition: self.disposition,
                reason: ProviderFinishReason::Error,
            },
        };
        Box::pin(async move {
            ProviderStreamItem::from_event(
                ProviderStreamEvent::new(cursor.sequence(), event).unwrap(),
            )
        })
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
