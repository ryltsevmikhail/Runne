use super::setup::PreparedFailureScenario;
use runne_application::ports::EventStore;
use runne_provider::*;
use runne_runtime::provider_execution::{ProviderEventJournalContext, RuntimeProviderExecution};
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};

pub(super) async fn seal_success_and_try_foreground(scenario: &PreparedFailureScenario) -> bool {
    let service = &scenario.service;
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
        attempt_id: scenario.provider_claim.attempt_id,
        fencing_token: scenario.provider_claim.fencing_token,
        call_digest_version: scenario.record.call_digest_version,
        profile_digest: scenario.record.profile_digest,
        runtime_generation: service.runtime_generation,
    };
    let provider = CompletedProvider;
    for sequence in 0..4 {
        runtime
            .next_and_commit(
                &provider,
                &scenario.stream,
                StreamCursor::new(sequence),
                &context,
            )
            .await
            .unwrap();
    }
    runtime.finalize_terminal_output(&context).unwrap();
    if runne_domain::task_run::TaskRun::replay(
        &scenario
            .harness
            .store
            .load_task_run(scenario.taskrun_id)
            .unwrap()
            .events,
    )
    .unwrap()
    .state()
        == runne_domain::task_run::TaskRunState::Cancelling
    {
        // The foreground execution leaves cancellation cleanup to the exact
        // pending-cancellation scanner.
        return false;
    }
    runtime
        .apply_terminal_output_for_attempt(
            scenario.provider_claim.attempt_id,
            &scenario.harness.terminal_application(),
        )
        .unwrap()
}

pub(super) async fn seal_success_only(scenario: &PreparedFailureScenario) {
    let service = &scenario.service;
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
        attempt_id: scenario.provider_claim.attempt_id,
        fencing_token: scenario.provider_claim.fencing_token,
        call_digest_version: scenario.record.call_digest_version,
        profile_digest: scenario.record.profile_digest,
        runtime_generation: service.runtime_generation,
    };
    for sequence in 0..4 {
        runtime
            .next_and_commit(
                &CompletedProvider,
                &scenario.stream,
                StreamCursor::new(sequence),
                &context,
            )
            .await
            .unwrap();
    }
    runtime.finalize_terminal_output(&context).unwrap();
}

struct CompletedProvider;

impl ProviderPort for CompletedProvider {
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
            1 => ProviderStreamEventKind::TextDelta {
                text: "recovered answer".into(),
            },
            2 => ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(1, 1, 0, 0).unwrap(),
            },
            _ => ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
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
        Box::pin(async { unreachable!() })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!() })
    }
}
