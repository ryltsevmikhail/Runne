use super::super::route::ExecutionRoute;
use super::super::*;
use runne_application::provider::ProviderExecutionStore;
use runne_provider::ProviderTerminalPricing;
use runne_runtime::provider_execution::{
    ProviderEventJournalContext, ProviderTerminalPersistence, RuntimeProviderExecution,
};
use runne_secure_store::ProviderJournalKeyring;

pub(super) async fn finish<K, S, P>(
    service: &DaemonCanonicalProviderService,
    job: CanonicalProviderExecutionJob,
    route: &ExecutionRoute<'_>,
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    context: &ProviderEventJournalContext,
    terminal_disposition: ProviderTerminalDisposition,
    attempt_id: runne_provider::DispatchAttemptId,
) -> Result<InternalProviderResult, CanonicalProviderExecutionError>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    execution
        .finalize_terminal_output(context)
        .map_err(super::super::super::projection::map_execution_error)?;
    if let Some(receipt) = foreground_cancellation_result(
        &service.conversation_store,
        job.started.taskrun_id,
        job.started.conversation_id,
        job.started.attempt_id,
        job.context.command_id,
        &job.context.idempotency_key,
    )? {
        return Ok(InternalProviderResult::Text(receipt));
    }
    match terminal_disposition {
        ProviderTerminalDisposition::Completed => {}
        ProviderTerminalDisposition::RemoteFailed
        | ProviderTerminalDisposition::RemoteIncomplete => {
            return service
                .finish_remote_terminal_failure(job)
                .map(InternalProviderResult::Text);
        }
        ProviderTerminalDisposition::CancelledUncertain => {
            return Err(CanonicalProviderExecutionError::Uncertain);
        }
    }
    let runtime_store = Arc::clone(&service.runtime_store);
    let profile = Arc::clone(route.profile);
    let keyring = Arc::clone(&service.keyring);
    let prohibited = Arc::clone(&service.prohibited_content);
    let scanner_store = Arc::clone(&service.scanner_store);
    let tail_store = Arc::clone(&service.tail_store);
    let application = ConversationProviderTerminalApplication::new(
        service.conversation_store.clone(),
        Arc::clone(&service.conversation_service),
    );
    let authority = service.runtime_authority_id;
    let generation = service.database_generation;
    let applied = tokio::task::spawn_blocking(move || {
        let matcher = ProhibitedContentCredentialMatcher::new(prohibited.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            tail_store.as_ref(),
            scanner_store.as_ref(),
            &matcher,
        );
        let execution = RuntimeProviderExecution::new(
            keyring.as_ref(),
            runtime_store.as_ref(),
            profile.as_ref(),
            prohibited.as_ref(),
            &redaction,
        );
        execution.preflight_existing_active_key(authority, generation)?;
        execution.apply_terminal_output_for_attempt(attempt_id, &application)
    })
    .await
    .map_err(|_| CanonicalProviderExecutionError::Uncertain)?
    .map_err(super::super::super::projection::map_execution_error)?;
    if !applied {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    let completed = service
        .conversation_store
        .load_text_generation_receipt_by_command(
            job.context.command_id,
            &job.context.idempotency_key,
        )
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    if completed.phase != runne_application::ports::TextGenerationPhase::Completed
        || completed.conversation_id != job.started.conversation_id
        || completed.taskrun_id != job.started.taskrun_id
        || completed.attempt_id != job.started.attempt_id
    {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    Ok(InternalProviderResult::Text(completed))
}
