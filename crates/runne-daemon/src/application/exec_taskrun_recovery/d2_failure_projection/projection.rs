use super::*;

impl DaemonAutomaticTaskRuns {
    pub(super) fn project_d2_interrupted(
        &self,
        candidate: runne_store::store::D2FailureRecoveryCandidate,
        cycle_id: runne_domain::id::CycleId,
        reason: runne_domain::conversation::GenerationFailureReason,
    ) -> Result<(), &'static str> {
        let (Some(conversation_id), Some(principal_id)) =
            (candidate.conversation_id, candidate.principal_id)
        else {
            return Err("restart_origin_missing");
        };
        let conversation = self
            .store
            .load_conversation(conversation_id)
            .map_err(|_| "restart_conversation")?;
        let mut events = conversation.events.iter().filter(|event| {
            matches!(event.payload(),
            ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
                if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.attempt_id)
        });
        let event = events.next().ok_or("restart_message_missing")?;
        if events.next().is_some() {
            return Err("restart_message_duplicate");
        }
        let ConversationEvent::UserMessageAppended {
            message_id, text, ..
        } = event.payload()
        else {
            return Err("restart_message_invalid");
        };
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let started = self
            .store
            .load_text_generation_receipt_by_command(command_id, &idempotency_key)
            .map_err(|_| "restart_started_receipt")?;
        if started.phase != TextGenerationPhase::Started
            || started.taskrun_id != candidate.taskrun_id
            || started.attempt_id != candidate.attempt_id
            || started.user_message_id != *message_id
            || started.conversation_version != event.sequence()
        {
            return Err("restart_started_mismatch");
        }
        let original = BeginConversationTextInput {
            conversation_id,
            expected_version: event.sequence().checked_sub(1).ok_or("restart_version")?,
            text: MessageText::new(text.as_str().to_owned()).map_err(|_| "restart_text")?,
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
            reason,
            Some(self.epoch),
        )
        .map_err(|_| "restart_failure_projection")?;
        Ok(())
    }
}
