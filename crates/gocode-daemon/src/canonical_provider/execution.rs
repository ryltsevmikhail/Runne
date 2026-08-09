use super::projection::*;
use super::*;

impl CanonicalProviderExecutionService for DaemonCanonicalOpenAiService {
    fn execute(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> gocode_provider::ProviderFuture<
        '_,
        Result<gocode_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            let call = project_call(&self.conversation_store, &job, self.profile.as_ref())?;
            let requested_input_tokens = u64::try_from(self.profile.max_input_bytes())
                .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let maximum_usage = ProviderUsage::new(
                requested_input_tokens,
                u64::from(self.profile.max_output_tokens()),
                0,
                0,
            )
            .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let max_cost_micros = self
                .profile
                .price_usage_micros(maximum_usage)
                .map_err(|_| CanonicalProviderExecutionError::Conflict)?;
            let coordinator = SqliteProviderDispatchCoordinator::new(
                self.dispatch_store.as_ref(),
                self.execution_store.as_ref(),
                self.adapter.as_ref(),
                self.adapter.as_ref(),
                self.prohibited_content.as_ref(),
            );
            let outcome = coordinator
                .dispatch(ProviderCoordinatorRequest {
                    call,
                    principal_id: job.context.principal_id.0.clone(),
                    conversation_id: job.started.conversation_id,
                    taskrun_id: job.started.taskrun_id,
                    execution_attempt_id: job.started.attempt_id,
                    profile_digest: self.profile.profile_digest(),
                    pricing_revision_digest: self.profile.pricing_revision_digest(),
                    requested_input_tokens,
                    requested_output_tokens: self.profile.max_output_tokens(),
                    max_cost_micros,
                    currency: self.profile.currency().to_owned(),
                    provider_idempotency_key: provider_idempotency_key(&job),
                })
                .await
                .map_err(map_admission_error)?;
            let ProviderCoordinatorOutcome::Streaming { binding } = outcome else {
                return Err(match outcome {
                    ProviderCoordinatorOutcome::Uncertain => {
                        CanonicalProviderExecutionError::Uncertain
                    }
                    ProviderCoordinatorOutcome::RejectedBeforeEffect { .. } => {
                        CanonicalProviderExecutionError::RejectedBeforeEffect
                    }
                    ProviderCoordinatorOutcome::Existing { state } => map_existing_state(state),
                    ProviderCoordinatorOutcome::Streaming { .. } => unreachable!(),
                });
            };
            let context = ProviderEventJournalContext {
                attempt_id: binding.attempt_id(),
                fencing_token: binding.fencing_token(),
                call_digest_version: binding.call_digest_version(),
                profile_digest: *binding.profile_digest(),
                runtime_generation: binding.runtime_generation(),
            };
            let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
            let redaction = ProviderEventRedactionBoundary::new(
                self.tail_store.as_ref(),
                self.scanner_store.as_ref(),
                &matcher,
            );
            let execution = RuntimeProviderExecution::new(
                self.keyring.as_ref(),
                self.runtime_store.as_ref(),
                self.profile.as_ref(),
                self.prohibited_content.as_ref(),
                &redaction,
            );
            execution
                .preflight_existing_active_key(self.runtime_authority_id, self.database_generation)
                .map_err(map_execution_error)?;
            let mut cursor = 0_u64;
            let terminal_disposition;
            loop {
                let item = execution
                    .next_and_commit(
                        self.adapter.as_ref(),
                        &binding.stream_id(),
                        StreamCursor::new(cursor),
                        &context,
                    )
                    .await
                    .map_err(map_execution_error)?;
                match item.event().kind() {
                    ProviderStreamEventKind::Finished { disposition, .. }
                    | ProviderStreamEventKind::ScannerCompleted { disposition, .. } => {
                        terminal_disposition = *disposition;
                        break;
                    }
                    _ => {}
                }
                cursor = cursor
                    .checked_add(1)
                    .ok_or(CanonicalProviderExecutionError::Uncertain)?;
            }
            execution
                .finalize_terminal_output(&context)
                .map_err(map_execution_error)?;
            match terminal_disposition {
                ProviderTerminalDisposition::Completed => {}
                ProviderTerminalDisposition::RemoteFailed => {
                    return Err(CanonicalProviderExecutionError::RemoteFailed);
                }
                ProviderTerminalDisposition::RemoteIncomplete => {
                    return Err(CanonicalProviderExecutionError::RemoteIncomplete);
                }
                ProviderTerminalDisposition::CancelledUncertain => {
                    return Err(CanonicalProviderExecutionError::Uncertain);
                }
            }
            let runtime_store = Arc::clone(&self.runtime_store);
            let profile = Arc::clone(&self.profile);
            let keyring = Arc::clone(&self.keyring);
            let prohibited = Arc::clone(&self.prohibited_content);
            let scanner_store = Arc::clone(&self.scanner_store);
            let tail_store = Arc::clone(&self.tail_store);
            let application = ConversationProviderTerminalApplication::new(
                self.conversation_store.clone(),
                Arc::clone(&self.conversation_service),
            );
            let attempt_id = binding.attempt_id();
            let authority = self.runtime_authority_id;
            let generation = self.database_generation;
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
            .map_err(map_execution_error)?;
            if !applied {
                return Err(CanonicalProviderExecutionError::Uncertain);
            }
            let completed = self
                .conversation_store
                .load_text_generation_receipt_by_command(
                    job.context.command_id,
                    &job.context.idempotency_key,
                )
                .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
            if completed.phase != gocode_application::ports::TextGenerationPhase::Completed
                || completed.conversation_id != job.started.conversation_id
                || completed.taskrun_id != job.started.taskrun_id
                || completed.attempt_id != job.started.attempt_id
            {
                return Err(CanonicalProviderExecutionError::Uncertain);
            }
            Ok(completed)
        })
    }
}
