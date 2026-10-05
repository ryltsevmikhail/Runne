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

#[cfg(test)]
#[path = "d2_failure_projection/authority_tests.rs"]
mod authority_tests;
#[cfg(test)]
#[path = "d2_failure_projection/lease_tests.rs"]
mod lease_tests;
#[path = "d2_failure_projection/restart.rs"]
mod restart;

fn runtime_authority_matches_node(authority: &str, node_id: &str) -> bool {
    match (
        uuid::Uuid::parse_str(authority),
        uuid::Uuid::parse_str(node_id),
    ) {
        (Ok(authority), Ok(node_id)) => authority == node_id,
        _ => false,
    }
}

impl DaemonAutomaticTaskRuns {
    pub(super) fn recover_d2_failure_projections(&self) -> Result<usize, &'static str> {
        self.renew_recovery_node_lease()?;
        if !runtime_authority_matches_node(&self.store.runtime_authority_id().0, &self.node_id.0) {
            return Err("failure_runtime_authority");
        }
        let mut cursor = None;
        let mut recovered = 0_usize;
        loop {
            let page = self
                .store
                .d2_failure_recovery_candidates(cursor, 32)
                .map_err(|_| "failure_candidate_query")?;
            let next = page
                .candidates
                .last()
                .map(|candidate| *candidate.taskrun_id.as_bytes());
            for candidate in page.candidates {
                match self.recover_one_d2_failure(candidate) {
                    Ok(true) => {
                        recovered = recovered.checked_add(1).ok_or("failure_count_overflow")?;
                    }
                    Ok(false) => {}
                    Err(stage) => {
                        if stage.starts_with("restart_") {
                            crate::application::tool_loop_plan::worker::diagnostics::d2_test_stage(
                                stage,
                            );
                        }
                        return Err(stage);
                    }
                }
            }
            if page.reached_end {
                return Ok(recovered);
            }
            cursor = next;
            if cursor.is_none() {
                return Err("failure_candidate_cursor");
            }
        }
    }

    fn recover_one_d2_failure(
        &self,
        candidate: runne_store::store::D2FailureRecoveryCandidate,
    ) -> Result<bool, &'static str> {
        self.renew_recovery_node_lease()?;
        if candidate.assignment.node_id != self.node_id
            || candidate.assignment.node_epoch >= self.epoch
        {
            return Ok(false);
        }
        let taskrun = self
            .store
            .load_task_run(candidate.taskrun_id)
            .map_err(|_| "failure_taskrun_read")?;
        if taskrun.current_version != candidate.terminal_version
            || taskrun.events.last().map(|event| *event.event_id())
                != Some(runne_domain::id::EventId::from_bytes(
                    candidate.terminal_event_id,
                ))
        {
            return Err("failure_terminal_binding");
        }
        let aggregate = TaskRun::replay(&taskrun.events).map_err(|_| "failure_taskrun_replay")?;
        if aggregate.state() == TaskRunState::Running {
            return self.stop_d2_after_restart(candidate, taskrun, aggregate);
        }
        if aggregate.state() == TaskRunState::Cancelling {
            if taskrun.events.last().is_none_or(|event| {
                event.payload() != &runne_domain::task_run::TaskRunEvent::CancellationRequested
            }) {
                return Ok(false);
            }
            let is_d2_profile = aggregate
                .snapshot_v1()
                .input()
                .and_then(|input| input.selected_profile())
                .is_some_and(|profile| profile.profile_id() == "runne-linux-agent-tools-v1");
            if !is_d2_profile {
                return Ok(false);
            }
            let budget = self
                .store
                .load_taskrun_tool_loop_budget_ref(candidate.taskrun_id)
                .map_err(|_| "cancel_budget_read")?;
            if budget
                .as_ref()
                .is_some_and(|budget| budget.attempt_id != candidate.attempt_id)
            {
                return Err("cancel_budget_attempt");
            }
            // Decode every durable invocation before projecting cancellation;
            // the store writer rechecks the full state/area proof atomically.
            let _invocations = self
                .store
                .load_taskrun_tool_invocations_for_taskrun(candidate.taskrun_id)
                .map_err(|_| "cancel_invocation_read")?;
            let (Some(conversation_id), Some(principal_id)) =
                (candidate.conversation_id, candidate.principal_id)
            else {
                return Ok(false);
            };
            let conversation = self
                .store
                .load_conversation(conversation_id)
                .map_err(|_| "cancel_conversation_read")?;
            let mut messages = conversation.events.iter().filter(|event| {
                matches!(event.payload(),
                    ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                        if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.attempt_id)
            });
            let event = messages.next().ok_or("cancel_original_message_missing")?;
            if messages.next().is_some() {
                return Err("cancel_original_message_duplicate");
            }
            let ConversationEvent::UserMessageAppended {
                message_id, text, ..
            } = event.payload()
            else {
                return Err("cancel_original_message_invalid");
            };
            let command_id = *event.command_id();
            let idempotency_key = event.idempotency_key().clone();
            let started = self
                .store
                .load_text_generation_receipt_by_command(command_id, &idempotency_key)
                .map_err(|_| "cancel_started_receipt")?;
            if started.phase != TextGenerationPhase::Started
                || started.taskrun_id != candidate.taskrun_id
                || started.attempt_id != candidate.attempt_id
                || started.conversation_id != conversation_id
                || started.user_message_id != *message_id
                || started.conversation_version != event.sequence()
            {
                return Err("cancel_started_receipt_mismatch");
            }
            let original = BeginConversationTextInput {
                conversation_id,
                expected_version: event.sequence().checked_sub(1).ok_or("cancel_version")?,
                text: MessageText::new(text.as_str().to_owned()).map_err(|_| "cancel_text")?,
            };
            let context = ApplicationCommandContext {
                command_id,
                idempotency_key,
                principal_id: runne_application::ports::PrincipalId(principal_id),
                actor: event.actor().clone(),
            };
            self.settle_d2_tool_loop_cancellation(
                &context,
                &original,
                &started,
                &candidate.assignment,
            )
            .map_err(|_| "cancel_projection")?;
            return Ok(true);
        }
        if aggregate.state() != TaskRunState::Failed {
            return Ok(false);
        }
        let mut failures = taskrun
            .events
            .iter()
            .filter_map(|event| match event.payload() {
                runne_domain::task_run::TaskRunEvent::LoopCycleCompleted {
                    cycle_id,
                    attempt_id,
                    disposition: runne_domain::agent_loop::LoopDisposition::Fail { reason, .. },
                } if *attempt_id == candidate.attempt_id
                    && (reason == "D2 tool approval or effect did not complete safely"
                        || reason == "provider_execution_rejected"
                        || reason == "interrupted_by_restart") =>
                {
                    Some((*cycle_id, reason.clone()))
                }
                _ => None,
            });
        let Some((cycle_id, loop_failure_reason)) = failures.next() else {
            return Ok(false);
        };
        if failures.next().is_some() {
            return Err("failure_cycle_duplicate");
        }
        let (Some(conversation_id), Some(principal_id)) =
            (candidate.conversation_id, candidate.principal_id)
        else {
            return Ok(false);
        };
        let conversation = self
            .store
            .load_conversation(conversation_id)
            .map_err(|_| "failure_conversation_read")?;
        let mut messages = conversation.events.iter().filter(|event| {
            matches!(event.payload(),
                ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                    if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.attempt_id)
        });
        let Some(event) = messages.next() else {
            return Err("failure_original_message_missing");
        };
        if messages.next().is_some() {
            return Err("failure_original_message_duplicate");
        }
        let ConversationEvent::UserMessageAppended {
            message_id, text, ..
        } = event.payload()
        else {
            return Err("failure_original_message_invalid");
        };
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let started = self
            .store
            .load_text_generation_receipt_by_command(command_id, &idempotency_key)
            .map_err(|_| "failure_started_receipt")?;
        if started.phase != TextGenerationPhase::Started
            || started.taskrun_id != candidate.taskrun_id
            || started.attempt_id != candidate.attempt_id
            || started.conversation_id != conversation_id
            || started.user_message_id != *message_id
            || started.conversation_version != event.sequence()
        {
            return Err("failure_started_receipt_mismatch");
        }
        let original = BeginConversationTextInput {
            conversation_id,
            expected_version: event.sequence().checked_sub(1).ok_or("failure_version")?,
            text: MessageText::new(text.as_str().to_owned()).map_err(|_| "failure_text")?,
        };
        let context = ApplicationCommandContext {
            command_id,
            idempotency_key,
            principal_id: runne_application::ports::PrincipalId(principal_id),
            actor: event.actor().clone(),
        };
        crate::application::tool_loop_failure::fail_d2_tool_loop(
            &self.store,
            &context,
            &original,
            &started,
            &candidate.assignment,
            cycle_id,
            if loop_failure_reason == "interrupted_by_restart" {
                runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
            } else {
                runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected
            },
            Some(self.epoch),
        )
        .map_err(|_| "failure_projection")?;
        Ok(true)
    }
}
