use super::super::fixture::Fixture;
use runne_application::ports::EventStore;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFinishReason, ProviderFuture,
    ProviderPort, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};

#[path = "source1_effects/read.rs"]
mod read;
#[path = "source1_effects/stream.rs"]
mod stream;
use runne_provider::{ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError};
use runne_runtime::provider_execution::{
    ProviderEventJournalContext, RuntimeProviderExecution, RuntimeProviderRemoteIdentityCommitter,
};
use runne_runtime::provider_redaction::{
    PreJournalProviderEvent, ProviderEventRedaction, ProviderRedactionError,
};

struct Events(Vec<ProviderStreamEvent>);

impl ProviderPort for Events {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call).map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
            .map_err(|error| PrepareError::Render(error.to_string()))
    }

    fn dispatch(
        &self,
        request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            Ok(ProviderStreamId::from_bytes(
                *request.attempt_id().as_bytes(),
            ))
        })
    }

    fn next<'a>(
        &'a self,
        _: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            self.0
                .get(cursor.sequence() as usize)
                .cloned()
                .map(ProviderStreamItem::from_event)
                .transpose()?
                .ok_or(StreamError::Closed)
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

struct AllowContent;

impl ProhibitedContentPort for AllowContent {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

struct Redaction;

impl ProviderEventRedaction for Redaction {
    fn scan_before_journal(
        &self,
        _: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<PreJournalProviderEvent, ProviderRedactionError> {
        Ok(PreJournalProviderEvent::Append(event.clone()))
    }

    fn terminal_disposition(
        &self,
        _: runne_provider::DispatchAttemptId,
    ) -> Result<Option<runne_provider::ScannerTerminalDisposition>, ProviderRedactionError> {
        Ok(Some(runne_provider::ScannerTerminalDisposition::Completed))
    }
}

struct UnusedPricing;

impl ProviderTerminalPricing for UnusedPricing {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: runne_provider::ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

fn terminal_events(usage: Option<runne_provider::ProviderUsage>) -> Vec<ProviderStreamEvent> {
    let usage = usage.map_or(ProviderStreamEventKind::UsageUnavailable, |usage| {
        ProviderStreamEventKind::Usage { usage }
    });
    vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "completed without usage".into(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(2, usage).unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: runne_provider::ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ]
}

fn stream_context(fixture: &Fixture) -> ProviderEventJournalContext {
    let row = fixture
        .database
        .connection()
        .query_row(
            "SELECT a.dispatch_attempt_id,a.fencing_token,a.generation,a.profile_digest,
                    p.call_digest_version
             FROM provider_execution_admissions a
             JOIN provider_prepared_requests p ON p.call_id=a.call_id
             WHERE a.taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap();
    let attempt = runne_provider::DispatchAttemptId::from_bytes(row.0.try_into().unwrap());
    let version = match row.4 {
        1 => ProviderCallDigestVersion::V1,
        2 => ProviderCallDigestVersion::V2,
        _ => panic!("known call digest version expected"),
    };
    ProviderEventJournalContext {
        attempt_id: attempt,
        fencing_token: u64::try_from(row.1).unwrap(),
        call_digest_version: version,
        profile_digest: row.3.try_into().unwrap(),
        runtime_generation: u64::try_from(row.2).unwrap(),
    }
}
