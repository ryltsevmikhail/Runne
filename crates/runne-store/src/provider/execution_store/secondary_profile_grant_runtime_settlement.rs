use super::Fixture;
use crate::provider::execution_store::DurableProviderAdmission;
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::{ProviderJournalKeyBinding, ProviderTerminalCommitOutcome};
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderFinishReason, ProviderFuture, ProviderPort,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem,
    ProviderTerminalDisposition, ProviderUsage, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};
use runne_runtime::provider_execution::{
    ProviderEventJournalContext, ProviderPricedUsage, ProviderTerminalPricing,
    ProviderTerminalPricingError, RuntimeProviderExecution,
};
use runne_runtime::provider_redaction::{
    PreJournalProviderEvent, ProviderEventRedaction, ProviderRedactionError,
};

struct Events;

impl ProviderPort for Events {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: runne_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call_for_digest_version(call, version)
    }

    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { Err(DispatchError::StreamNotFound) })
    }

    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        let event = match cursor.sequence() {
            0 => ProviderStreamEvent::new(0, ProviderStreamEventKind::Started),
            1 => ProviderStreamEvent::new(
                1,
                ProviderStreamEventKind::TextDelta {
                    text: "secondary result".to_owned(),
                },
            ),
            2 => ProviderStreamEvent::new(
                2,
                ProviderStreamEventKind::Usage {
                    usage: ProviderUsage::new(500, 900, 0, 0).unwrap(),
                },
            ),
            3 => ProviderStreamEvent::new(
                3,
                ProviderStreamEventKind::Finished {
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                },
            ),
            _ => return Box::pin(async { Err(StreamError::EventAfterTerminal) }),
        };
        let _ = stream;
        Box::pin(async move { ProviderStreamItem::from_event(event?) })
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

struct Guard;

impl ProhibitedContentPort for Guard {
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

struct Pricing;

impl ProviderTerminalPricing for Pricing {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        ProviderPricedUsage::new(40_000, "USD".to_owned())
    }
}

pub(super) fn settle(
    fixture: &Fixture,
    admission: &DurableProviderAdmission,
) -> ProviderTerminalCommitOutcome {
    journal_only(fixture, admission);
    finalize(fixture, admission)
}

pub(super) fn journal_only(fixture: &Fixture, admission: &DurableProviderAdmission) {
    poll_events(fixture, admission);
}

pub(in crate::provider::execution_store) fn finalize(
    fixture: &Fixture,
    admission: &DurableProviderAdmission,
) -> ProviderTerminalCommitOutcome {
    let keyring =
        crate::provider::execution_store::online_proof_test_support::TestKeyring::new([(
            1, [7; 32],
        )]);
    let pricing = Pricing;
    let guard = Guard;
    let redaction = Redaction;
    let runtime =
        RuntimeProviderExecution::new(&keyring, &fixture.store, &pricing, &guard, &redaction);
    runtime
        .use_existing_active_key(key_binding())
        .expect("existing test journal key");
    runtime
        .finalize_terminal_output(&context(admission))
        .expect("runtime-owned terminal settlement")
}

fn poll_events(fixture: &Fixture, admission: &DurableProviderAdmission) {
    use futures::executor::block_on;

    let keyring =
        crate::provider::execution_store::online_proof_test_support::TestKeyring::new([(
            1, [7; 32],
        )]);
    let pricing = Pricing;
    let guard = Guard;
    let redaction = Redaction;
    let runtime =
        RuntimeProviderExecution::new(&keyring, &fixture.store, &pricing, &guard, &redaction);
    runtime
        .use_existing_active_key(key_binding())
        .expect("existing test journal key");
    let provider = Events;
    let stream = ProviderStreamId::from_bytes([44; 16]);
    for sequence in 0..4 {
        block_on(runtime.next_and_commit(
            &provider,
            &stream,
            StreamCursor::new(sequence),
            &context(admission),
        ))
        .unwrap_or_else(|error| panic!("runtime event {sequence} was rejected: {error:?}"));
    }
}

fn context(admission: &DurableProviderAdmission) -> ProviderEventJournalContext {
    ProviderEventJournalContext {
        attempt_id: admission.claim().attempt_id,
        fencing_token: admission.claim().fencing_token,
        call_digest_version: runne_provider::ProviderCallDigestVersion::V2,
        profile_digest: [2; 32],
        runtime_generation: 11,
    }
}

fn key_binding() -> ProviderJournalKeyBinding {
    ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], 7).unwrap()
}
