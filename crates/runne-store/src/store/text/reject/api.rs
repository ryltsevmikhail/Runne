use super::*;
use runne_application::ports::RejectTextGenerationAfterD2ToolLoopRestartCommit;

impl StoreTransaction {
    pub(in crate::store::text) fn reject_text_generation_impl(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_inner(payload, None)
    }

    pub(in crate::store::text) fn reject_text_generation_after_d2_tool_loop_restart_impl(
        &self,
        payload: RejectTextGenerationAfterD2ToolLoopRestartCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        let evidence = payload.evidence;
        self.reject_text_generation_inner(
            RejectTextGenerationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_taskrun_version: payload.expected_taskrun_version,
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
            Some(evidence),
        )
    }
}
