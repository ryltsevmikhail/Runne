use gocode_application::ports::TextGenerationReceipt;
use gocode_application::provider::ProviderAuthorityIssueRequest;
use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest, ProviderCall,
    ProviderCallId, ProviderFinishReason, ProviderFuture, ProviderId, ProviderPort,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem,
    ProviderTerminalDisposition, ProviderUsage, ReconcileRequest, ReconciliationDisposition,
    StreamCursor, StreamError,
};
use gocode_runtime::provider_execution::{ProviderEventJournalContext, RuntimeProviderExecution};
use gocode_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
};

use super::super::DaemonCanonicalOpenAiService;

pub(super) async fn create(
    service: &DaemonCanonicalOpenAiService,
    started: TextGenerationReceipt,
) -> gocode_provider::DispatchAttemptId {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "v1",
        )
        .unwrap(),
        [2; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: service.profile.profile_digest(),
    };
    service.dispatch_store.persist_prepared(&record).unwrap();
    let ProviderAuthorityIssueOutcome::Winner(admitted) = service
        .execution_store
        .issue(&ProviderAuthorityIssueRequest {
            principal_id: "local-owner".into(),
            conversation_id: started.conversation_id,
            taskrun_id: started.taskrun_id,
            execution_attempt_id: started.attempt_id,
            prepared: ContractPreparedProviderRecord {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
            },
            pricing_revision_digest: service.profile.pricing_revision_digest(),
            requested_input_tokens: 512,
            requested_output_tokens: 1_024,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: "fixture-pending-recovery".into(),
        })
        .unwrap()
    else {
        panic!("fixture admission must win");
    };
    service
        .dispatch_store
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: admitted.claim().attempt_id,
            fencing_token: admitted.claim().fencing_token,
            stream_id: ProviderStreamId::from_bytes([3; 16]),
        })
        .unwrap();
    let matcher = ProhibitedContentCredentialMatcher::new(service.prohibited_content.as_ref());
    let redaction = ProviderEventRedactionBoundary::new(
        service.tail_store.as_ref(),
        service.scanner_store.as_ref(),
        &matcher,
    );
    let runtime = RuntimeProviderExecution::new(
        service.keyring.as_ref(),
        service.execution_store.as_ref(),
        service.profile.as_ref(),
        service.prohibited_content.as_ref(),
        &redaction,
    );
    runtime
        .preflight_existing_active_key(service.runtime_authority_id, service.database_generation)
        .unwrap();
    let context = ProviderEventJournalContext {
        attempt_id: admitted.claim().attempt_id,
        fencing_token: admitted.claim().fencing_token,
        call_digest_version: record.call_digest_version,
        profile_digest: record.profile_digest,
        runtime_generation: service.runtime_generation,
    };
    let provider = FixtureProvider(events());
    for sequence in 0..4 {
        runtime
            .next_and_commit(
                &provider,
                &ProviderStreamId::from_bytes([3; 16]),
                StreamCursor::new(sequence),
                &context,
            )
            .await
            .unwrap();
    }
    runtime.finalize_terminal_output(&context).unwrap();
    context.attempt_id
}

fn events() -> Vec<ProviderStreamEvent> {
    vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "answer".into(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(500, 900, 0, 0).unwrap(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ]
}

struct FixtureProvider(Vec<ProviderStreamEvent>);

impl ProviderPort for FixtureProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        PreparedRequest::from_call(call)
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: gocode_provider::ProviderCallDigestVersion,
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
        let event = self.0[cursor.sequence() as usize].clone();
        Box::pin(async move { ProviderStreamItem::from_event(event) })
    }
    fn cancel(
        &self,
        _: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
}
use gocode_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
