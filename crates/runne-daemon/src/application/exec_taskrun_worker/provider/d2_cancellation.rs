use super::*;

impl DaemonAutomaticTaskRuns {
    pub(in crate::application) fn settle_d2_tool_loop_cancellation(
        &self,
        context: &ApplicationCommandContext,
        original: &BeginConversationTextInput,
        started: &TextGenerationReceipt,
        assignment: &TaskRunAssignmentIdentity,
    ) -> Result<(), ()> {
        use crate::application::tool_loop_plan::worker::diagnostics::d2_test_stage;
        use runne_application::ports::EventStore;

        d2_test_stage("cancel_d2_begin");
        let stream = self
            .store
            .load_task_run(assignment.taskrun_id)
            .map_err(|_| {
                d2_test_stage("cancel_d2_stream_error");
            })?;
        if stream.current_version <= started.taskrun_version {
            d2_test_stage("cancel_d2_old_head");
            return Err(());
        }
        let task = TaskRun::replay(&stream.events).map_err(|_| {
            d2_test_stage("cancel_d2_replay_error");
        })?;
        if task.state() != TaskRunState::Cancelling {
            d2_test_stage("cancel_d2_not_cancelling");
            return Err(());
        }
        let node_id = uuid::Uuid::parse_str(&assignment.node_id.0)
            .map_err(|_| ())?
            .into_bytes();
        match self.text.finish_text(
            context,
            FinishConversationTextInput {
                original: original.clone(),
                started: started.clone(),
                completion: ConversationTextCompletion::D2ToolLoopCancellation {
                    evidence: runne_application::ports::D2ToolLoopCancellationEvidence {
                        node_id,
                        node_epoch: assignment.node_epoch,
                        fence: assignment.fence.0,
                        cancellation_taskrun_version: stream.current_version,
                    },
                },
            },
        ) {
            Ok(_) => {
                d2_test_stage("cancel_d2_finished");
                Ok(())
            }
            Err(error) => {
                use runne_application::conversation_text_service::ConversationTextServiceError as E;
                let stage = match error {
                    E::Conflict => "cancel_d2_finish_error_conflict",
                    E::ReceiptMismatch => "cancel_d2_finish_error_receipt",
                    E::Commit(runne_application::ports::CommitError::StorageFailure(kind)) => {
                        use runne_application::ports::StorageFailureKind as S;
                        match kind {
                            S::IntegrityViolation
                            | S::CorruptData
                            | S::UnsupportedSchema
                            | S::PolicyDenied => "cancel_d2_finish_error_storage_integrity",
                            S::WriterFenced => "cancel_d2_finish_error_storage_fenced",
                            S::Unavailable => "cancel_d2_finish_error_storage_unavailable",
                        }
                    }
                    E::Commit(runne_application::ports::CommitError::VersionConflict {
                        ..
                    }) => "cancel_d2_finish_error_conflict",
                    E::Commit(_) => "cancel_d2_finish_error_storage_other",
                    E::StoredDataUnavailable => "cancel_d2_finish_error_storage_unavailable",
                    E::ConversationDomain(_) | E::TaskRunDomain => "cancel_d2_finish_error_domain",
                    _ => "cancel_d2_finish_error_other",
                };
                d2_test_stage(stage);
                Err(())
            }
        }
    }
}
