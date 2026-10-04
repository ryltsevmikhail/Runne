use super::super::projection::*;
use super::super::*;

impl DaemonCanonicalProviderService {
    pub(super) fn execute_internal(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: Option<runne_application::ports::TaskRunAssignmentIdentity>,
        selected_profile: Option<runne_domain::task_run::SelectedProviderProfile>,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            let route = self
                .execution_route(selected_profile.as_ref())
                .ok_or(CanonicalProviderExecutionError::RejectedBeforeEffect)?;
            // Recheck trust only after any prior operation has settled; the
            // gate stays held through terminal application below.
            let _dispatch_guard = self.acquire_dispatch_gate().await;
            // NM-06: re-check the CURRENT trust revision right before any
            // provider delivery. Revocations and authority failures deny the
            // dispatch before the coordinator runs (fail-closed, no durable
            // side effects; `PolicyDenied` is the closed typed outcome).
            if let Some(trust) = &self.trust {
                // NM-06: the gate consults the conversation's durable
                // context marker and, for workspace-scoped conversations,
                // the governed project's CURRENT revision. Revocations
                // between preparation (begin_text) and dispatch deny here.
                // A workspace/unmarked retention gap denies here too
                // (fail-closed); only an explicit TextOnly gap passes the
                // gate and then fails the projection on its partial stream.
                if trust
                    .ensure_conversation_trusted(
                        job.context.principal_id.0.as_str(),
                        job.started.conversation_id,
                    )
                    .is_err()
                {
                    execution_diagnostics::record("provider_trust_gate", false);
                    return Err(CanonicalProviderExecutionError::PolicyDenied);
                }
                execution_diagnostics::record("provider_trust_gate", true);
            }
            let call = match project_call(
                &self.conversation_store,
                &job,
                route.profile.as_ref(),
                route.provider_id,
                route.model_id,
                route.model_revision,
            ) {
                Ok(call) => {
                    execution_diagnostics::record("provider_projection_ready", true);
                    call
                }
                Err(error) => {
                    let stage = execution_diagnostics::projection_failure_stage(error);
                    execution_diagnostics::record(stage, false);
                    return Err(error);
                }
            };
            let (requested_input_tokens, requested_output_tokens, max_cost_micros) =
                super::route::request_ceiling(route.profile.as_ref())?;
            let provider_identity = runne_provider::ProviderId::new(route.provider_id)
                .map_err(|_| CanonicalProviderExecutionError::RejectedBeforeEffect)?;
            let request_intents: Arc<dyn runne_provider::ProviderRecoveryDispatchContextProvider> =
                Arc::new(
                    runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter::new(
                        Arc::clone(&self.keyring),
                        Arc::clone(&self.execution_store),
                    ),
                );
            let credential = runne_store::provider::CredentialDispatchAuthority::new(
                route.credential_store.as_ref(),
                &self.launch_capability,
            );
            let effect = super::dispatch_binding::OnlineDispatchFence::new(
                super::dispatch_binding::OnlineDispatchFenceConfig {
                    authority: credential,
                    inner: route.adapter,
                    trust: self.trust.as_ref().map(|trust| {
                        (
                            trust.clone(),
                            job.context.principal_id.0.clone(),
                            job.started.conversation_id,
                        )
                    }),
                    taskrun: assignment.map(|identity| {
                        (
                            identity,
                            job.started.taskrun_version,
                            route.profile.profile_digest(),
                        )
                    }),
                    taskrun_store: &self.conversation_store,
                    request_intents,
                    provider_id: provider_identity.clone(),
                    credential_realm: provider_identity,
                    profile_id: route.profile.profile_id().to_owned(),
                },
            );
            let coordinator = SqliteProviderDispatchCoordinator::new_with_budget(
                self.dispatch_store.as_ref(),
                self.execution_store.as_ref(),
                credential,
                route.adapter,
                &effect,
                self.prohibited_content.as_ref(),
                runne_api::is_subscription_provider(route.provider_id),
                Some(route.credential_store.clone()),
            );
            // Keep the launch lease stable from admission through terminal
            // application; renewal cannot change an in-flight admission's expiry.
            self.renew_launch_authority()?;
            let coordinator_request = ProviderCoordinatorRequest {
                call,
                principal_id: job.context.principal_id.0.clone(),
                conversation_id: job.started.conversation_id,
                taskrun_id: job.started.taskrun_id,
                execution_attempt_id: job.started.attempt_id,
                profile_digest: route.profile.profile_digest(),
                pricing_revision_digest: route.profile.pricing_revision_digest(),
                requested_input_tokens,
                requested_output_tokens,
                max_cost_micros,
                currency: route.profile.currency().to_owned(),
                provider_idempotency_key: provider_idempotency_key(&job),
            };
            let outcome = match route.admission {
                super::route::RouteAdmission::Primary => {
                    coordinator.dispatch(coordinator_request).await
                }
                super::route::RouteAdmission::Secondary(grant) => {
                    coordinator
                        .dispatch_secondary_profile(coordinator_request, grant)
                        .await
                }
            };
            let outcome = match outcome {
                Ok(outcome) => {
                    let stage = execution_diagnostics::outcome_stage(&outcome);
                    let succeeded = !matches!(&outcome, ProviderCoordinatorOutcome::Uncertain);
                    execution_diagnostics::record(stage, succeeded);
                    outcome
                }
                Err(error) => {
                    let stage = execution_diagnostics::admission_failure_stage(&error);
                    execution_diagnostics::record(stage, false);
                    return Err(map_admission_error(error));
                }
            };
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
                attempt_id: binding.execution().attempt_id(),
                fencing_token: binding.execution().fencing_token(),
                call_digest_version: binding.execution().call_digest_version(),
                profile_digest: *binding.execution().profile_digest(),
                runtime_generation: binding.execution().runtime_generation(),
            };
            let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
            let redaction = ProviderEventRedactionBoundary::new(
                self.tail_store.as_ref(),
                self.scanner_store.as_ref(),
                &matcher,
            )
            .with_observer(&super::redaction_diagnostics::QUALIFICATION_OBSERVER);
            let execution = RuntimeProviderExecution::new(
                self.keyring.as_ref(),
                self.runtime_store.as_ref(),
                route.profile.as_ref(),
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
                        route.adapter,
                        &binding.execution().stream_id(),
                        StreamCursor::new(cursor),
                        &context,
                    )
                    .await
                    .map_err(map_execution_error)?;
                let kind = item.event().kind().clone();
                match kind {
                    ProviderStreamEventKind::Finished { disposition, .. }
                    | ProviderStreamEventKind::ScannerCompleted { disposition, .. } => {
                        terminal_disposition = disposition;
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
            if let Some(receipt) = foreground_cancellation_result(
                &self.conversation_store,
                job.started.taskrun_id,
                job.started.conversation_id,
                job.started.attempt_id,
                job.context.command_id,
                &job.context.idempotency_key,
            )? {
                return Ok(receipt);
            }
            match terminal_disposition {
                ProviderTerminalDisposition::Completed => {}
                ProviderTerminalDisposition::RemoteFailed
                | ProviderTerminalDisposition::RemoteIncomplete => {
                    // The terminal usage was already priced and settled by
                    // finalize_terminal_output. Close the exact begun
                    // generation with the factual failure reason here, so
                    // the worker does not replace it with a generic error
                    // path or leave it Running until boot recovery.
                    return self.finish_remote_terminal_failure(job);
                }
                ProviderTerminalDisposition::CancelledUncertain => {
                    return Err(CanonicalProviderExecutionError::Uncertain);
                }
            }
            let runtime_store = Arc::clone(&self.runtime_store);
            let profile = Arc::clone(route.profile);
            let keyring = Arc::clone(&self.keyring);
            let prohibited = Arc::clone(&self.prohibited_content);
            let scanner_store = Arc::clone(&self.scanner_store);
            let tail_store = Arc::clone(&self.tail_store);
            let application = ConversationProviderTerminalApplication::new(
                self.conversation_store.clone(),
                Arc::clone(&self.conversation_service),
            );
            let attempt_id = binding.execution().attempt_id();
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
            if completed.phase != runne_application::ports::TextGenerationPhase::Completed
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
