use super::super::projection::*;
use super::super::*;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
use super::InternalProviderResult;
mod call;
mod dispatch;
mod final_text;
mod stream;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod terminal_artifact;
mod text_terminal;
mod tool_context;

impl DaemonCanonicalProviderService {
    pub(super) fn execute_internal(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: Option<runne_application::ports::TaskRunAssignmentIdentity>,
        selected_profile: Option<runne_domain::task_run::SelectedProviderProfile>,
        require_tool_mode: bool,
        tool_round: Option<super::D2ProviderRound>,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<super::InternalProviderResult, CanonicalProviderExecutionError>,
    > {
        Box::pin(async move {
            let route = self
                .execution_route(selected_profile.as_ref())
                .ok_or(CanonicalProviderExecutionError::RejectedBeforeEffect)?;
            if route.tool_mode != require_tool_mode {
                return Err(CanonicalProviderExecutionError::RejectedBeforeEffect);
            }
            if route.tool_mode != tool_round.is_some() {
                return Err(CanonicalProviderExecutionError::RejectedBeforeEffect);
            }
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
            if tool_round
                .as_ref()
                .is_some_and(|round| round.round_index > 2)
            {
                return Err(CanonicalProviderExecutionError::RejectedBeforeEffect);
            }
            let round_call_id = match (assignment.as_ref(), tool_round.as_ref()) {
                (Some(assignment), Some(round)) => {
                    Some(tool_context::round_call_id(&job, assignment, round))
                }
                (None, Some(_)) => {
                    return Err(CanonicalProviderExecutionError::RejectedBeforeEffect);
                }
                _ => None,
            };
            let tool_results = match (assignment.as_ref(), tool_round.as_ref()) {
                (Some(assignment), Some(round)) => {
                    tool_context::previous_results(self, assignment, round, &route)?
                }
                _ => Vec::new(),
            };
            let call = call::project(
                &self.conversation_store,
                &job,
                &route,
                tool_results,
                round_call_id,
            )?;
            let binding = dispatch::start(
                self,
                &job,
                &route,
                assignment.as_ref(),
                tool_round.as_ref(),
                call,
                round_call_id,
            )
            .await?;
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
            let stream_id = binding.execution().stream_id();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
            let mut cursor = 0_u64;
            let terminal_disposition;
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            let mut proposal = None;
            let mut collector = if route.tool_mode {
                Some(
                    runne_runtime::provider_tool::CommittedToolProposalCollector::new(
                        0,
                        String::new(),
                        None,
                        false,
                        8 * 1024,
                    )
                    .map_err(|_| CanonicalProviderExecutionError::RemoteIncomplete)?,
                )
            } else {
                None
            };
            loop {
                if bounded_tool_poll_exhausted(
                    route.tool_mode,
                    cursor,
                    tokio::time::Instant::now() >= deadline,
                ) {
                    stream::freeze_and_cancel(
                        self.execution_store.as_ref(),
                        route.adapter,
                        &stream_id,
                        &context,
                    )
                    .await;
                    return Err(CanonicalProviderExecutionError::Uncertain);
                }
                let (item, outcome) = stream::poll_next(
                    &execution,
                    route.adapter,
                    &stream_id,
                    StreamCursor::new(cursor),
                    &context,
                    self.execution_store.as_ref(),
                    collector.as_mut(),
                    Some(deadline),
                    || {
                        foreground_cancellation_result(
                            &self.conversation_store,
                            job.started.taskrun_id,
                            job.started.conversation_id,
                            job.started.attempt_id,
                            job.context.command_id,
                            &job.context.idempotency_key,
                        )
                        .map_or(true, |receipt| receipt.is_some())
                    },
                )
                .await?;
                if let Some(
                    runne_runtime::provider_tool::ProviderToolLoopOutcome::ToolProposalReady {
                        call,
                        ..
                    },
                ) = outcome
                {
                    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                    {
                        proposal = Some(call);
                    }
                    #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
                    let _ = call;
                }
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
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            if route.tool_mode {
                if terminal_disposition != ProviderTerminalDisposition::Completed {
                    return Err(CanonicalProviderExecutionError::RemoteIncomplete);
                }
                if foreground_cancellation_result(
                    &self.conversation_store,
                    job.started.taskrun_id,
                    job.started.conversation_id,
                    job.started.attempt_id,
                    job.context.command_id,
                    &job.context.idempotency_key,
                )?
                .is_some()
                {
                    return Err(CanonicalProviderExecutionError::Uncertain);
                }
                execution
                    .finalize_tool_terminal_output(&context)
                    .map_err(map_execution_error)?;
                let artifact = terminal_artifact::load(
                    self.execution_store.as_ref(),
                    binding.execution().attempt_id(),
                    route.profile.profile_digest(),
                    binding.execution().runtime_generation(),
                )?;
                let Some(artifact) = artifact else {
                    return Err(CanonicalProviderExecutionError::Uncertain);
                };
                let sources = terminal_artifact::sources(
                    self.execution_store.as_ref(),
                    binding.execution().attempt_id(),
                    route.profile.profile_digest(),
                    binding.execution().runtime_generation(),
                    if proposal.is_some() { 4 } else { 7 },
                )?;
                return match proposal {
                    Some(call) => {
                        if !sources.iter().any(|source| source.event_kind == 4)
                            || !sources
                                .iter()
                                .any(|source| source.event_kind == 5 && source.terminal)
                        {
                            return Err(CanonicalProviderExecutionError::Uncertain);
                        }
                        Ok(InternalProviderResult::ToolRound(
                            super::D2ProviderRoundOutcome::Proposal { call, sources },
                        ))
                    }
                    None => Ok(InternalProviderResult::ToolRound(
                        super::D2ProviderRoundOutcome::FinalStop {
                            terminal: artifact,
                            sources,
                        },
                    )),
                };
            }
            #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
            if route.tool_mode {
                return Err(CanonicalProviderExecutionError::Uncertain);
            }
            text_terminal::finish(
                self,
                job,
                &route,
                &execution,
                &context,
                terminal_disposition,
                binding.execution().attempt_id(),
            )
            .await
        })
    }
}

fn bounded_tool_poll_exhausted(tool_mode: bool, cursor: u64, deadline_reached: bool) -> bool {
    tool_mode && (cursor >= 512 || deadline_reached)
}

#[cfg(test)]
#[path = "execute/bounds_tests.rs"]
mod bounds_tests;
