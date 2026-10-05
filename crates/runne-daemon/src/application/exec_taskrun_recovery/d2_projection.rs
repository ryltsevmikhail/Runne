use super::super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::{
    commands::BeginConversationTextInput,
    ports::{ApplicationCommandContext, ConversationRepository, EventStore, TextGenerationPhase},
};
use runne_domain::{
    conversation::ConversationEvent,
    message::MessageText,
    task_run::{TaskRun, TaskRunState},
};
use runne_store::store::D2CompletionRecoveryCandidate;

impl DaemonAutomaticTaskRuns {
    pub(super) fn recover_d2_terminal_projections(&self) -> Result<usize, &'static str> {
        let provider = self.provider.as_ref();
        let mut cursor = None;
        let mut recovered = 0_usize;
        loop {
            let page = self
                .store
                .d2_completion_recovery_candidates(cursor, 32)
                .map_err(|_| "candidate_query")?;
            let next_cursor = page
                .candidates
                .last()
                .map(|candidate| *candidate.taskrun_id.as_bytes());
            for candidate in page.candidates {
                if self.recover_one_d2_projection(provider, candidate)? {
                    recovered = recovered.checked_add(1).ok_or("count_overflow")?;
                }
            }
            if page.reached_end {
                return Ok(recovered);
            }
            cursor = next_cursor;
            if cursor.is_none() {
                return Err("candidate_cursor");
            }
        }
    }

    fn recover_one_d2_projection(
        &self,
        provider: Option<
            &std::sync::Arc<crate::canonical_provider::DaemonCanonicalProviderService>,
        >,
        candidate: D2CompletionRecoveryCandidate,
    ) -> Result<bool, &'static str> {
        let stream = self
            .store
            .load_task_run(candidate.taskrun_id)
            .map_err(|_| "taskrun_read")?;
        if stream.current_version != candidate.taskrun_head {
            return Err("taskrun_head");
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| "taskrun_replay")?;
        if task.state() != TaskRunState::Succeeded {
            // A round-two outbox can exist before LoopCycleCompleted. It is
            // deliberately left frozen for the active worker/recovery path.
            return Ok(false);
        }
        let Some(provider) = provider else {
            // Keep an already-completed projection pending if its original
            // provider key/profile is unavailable; never block daemon boot.
            return Ok(false);
        };
        let mut final_cycle = stream
            .events
            .iter()
            .filter_map(|event| match event.payload() {
                runne_domain::task_run::TaskRunEvent::LoopCycleCompleted {
                    cycle_id,
                    attempt_id,
                    disposition:
                        runne_domain::agent_loop::LoopDisposition::Complete {
                            plan_evaluation_ref,
                        },
                } => Some((*cycle_id, *attempt_id, plan_evaluation_ref.clone())),
                _ => None,
            });
        let (cycle_id, attempt_id, evaluation_ref) = final_cycle.next().ok_or("cycle_missing")?;
        if final_cycle.next().is_some()
            || cycle_id != candidate.cycle_id
            || attempt_id != candidate.attempt_id
        {
            return Err("cycle_conflict");
        }
        let verified = crate::application::tool_authorities::verify_historical_completed(
            self.store.clone(),
            self.provider.clone(),
            self.root_admission.clone(),
            candidate.taskrun_id,
        )
        .map_err(|_| "historical_evaluation")?;
        if verified.reference != evaluation_ref {
            return Err("evaluation_mismatch");
        }
        let conversation = self
            .store
            .load_conversation(candidate.conversation_id)
            .map_err(|_| "conversation_read")?;
        let mut starts = conversation.events.iter().filter(|event| {
            matches!(event.payload(),
            ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.attempt_id)
        });
        let event = starts.next().ok_or("original_message_missing")?;
        if starts.next().is_some() {
            return Err("original_message_duplicate");
        }
        let ConversationEvent::UserMessageAppended {
            message_id, text, ..
        } = event.payload()
        else {
            return Err("original_message_invalid");
        };
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let started = self
            .store
            .load_text_generation_receipt_by_command(command_id, &idempotency_key)
            .map_err(|_| "started_receipt")?;
        if started.phase != TextGenerationPhase::Started
            || started.taskrun_id != candidate.taskrun_id
            || started.attempt_id != candidate.attempt_id
            || started.conversation_id != candidate.conversation_id
            || started.user_message_id != *message_id
            || started.conversation_version != event.sequence()
            || started.taskrun_version != candidate.original_claim_version
        {
            return Err("started_receipt_mismatch");
        }
        let original = BeginConversationTextInput {
            conversation_id: candidate.conversation_id,
            expected_version: event
                .sequence()
                .checked_sub(1)
                .ok_or("conversation_version")?,
            text: MessageText::new(text.as_str().to_owned()).map_err(|_| "message_text")?,
        };
        let context = ApplicationCommandContext {
            command_id,
            idempotency_key,
            principal_id: runne_application::ports::PrincipalId(candidate.principal_id.clone()),
            actor: event.actor().clone(),
        };
        let job = runne_runtime::canonical_provider_execution::CanonicalProviderExecutionJob {
            context: context.clone(),
            original: original.clone(),
            started: started.clone(),
        };
        let terminal = crate::canonical_provider::D2ToolTerminalRef {
            attempt_id: runne_provider::DispatchAttemptId::from_bytes(
                candidate.terminal_attempt_id,
            ),
            outbox_id: candidate.terminal_outbox_id,
            terminal_sequence: candidate.terminal_sequence,
            settlement_digest: *candidate.settlement_digest.as_bytes(),
            fencing_token: candidate.fencing_token,
            call_digest_version: candidate.call_digest_version,
            profile_digest: candidate.profile_digest,
            runtime_generation: candidate.runtime_generation,
        };
        let final_text = provider
            .recover_d2_final_text(&job, &terminal)
            .map_err(|_| "final_stop_authentication")?;
        let sources = candidate
            .terminal_sources
            .iter()
            .map(
                |source| runne_store::store::taskrun_tool_invocation::ToolSourceRef {
                    dispatch_attempt_id: source.dispatch_attempt_id,
                    sequence: source.sequence,
                    event_kind: source.event_kind,
                    terminal: source.terminal,
                    plaintext_digest: source.plaintext_digest,
                    profile_digest: source.profile_digest,
                    runtime_generation: source.runtime_generation,
                },
            )
            .collect::<Vec<_>>();
        crate::application::tool_loop_completion::complete_d2_tool_loop(
            &self.store,
            &context,
            &original,
            &started,
            &candidate.assignment,
            cycle_id,
            evaluation_ref,
            &terminal,
            &sources,
            final_text,
        )
        .map_err(|_| "completion_projection")?;
        Ok(true)
    }
}
