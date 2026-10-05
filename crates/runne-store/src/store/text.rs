mod begin;
mod claimed_begin;
mod claimed_begin_receipt;
mod claimed_begin_validation;
mod d2_tool_loop_completion;
mod d2_tool_loop_restart;
mod finish;
mod lookup;
mod reject;
mod remote_artifact_finish_guard;
mod remote_artifact_reject_guard;
mod terminal_cancellation;
mod terminal_cancellation_validation;
mod terminal_occupation;

use super::parse_helpers::storage_failure;
use super::*;
use runne_application::ports::RejectTextGenerationAfterPreEffectCancellationCommit;
use runne_application::ports::RejectTextGenerationAfterTerminalCancellationCommit;
use runne_application::ports::RejectTextGenerationAfterUnknownTerminalCancellationCommit;

pub(crate) fn verify_d2_cancelled_provider_rounds(
    connection: &rusqlite::Connection,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
    original_claim_version: u64,
    cancel_version: u64,
) -> Result<(), CommitError> {
    terminal_cancellation_validation::verify_d2_cancelled_provider_rounds(
        connection,
        taskrun_id,
        attempt_id,
        evidence,
        original_claim_version,
        cancel_version,
    )
}

impl ConversationTextRepository for StoreTransaction {
    fn validate_d2_tool_loop_cancellation_receipt(
        &self,
        receipt: &runne_application::ports::TextGenerationReceipt,
        evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
    ) -> Result<bool, CommitError> {
        if receipt.phase != TextGenerationPhase::Rejected {
            return Ok(false);
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        super::test_support_diagnostics::on_error(
            "cancel.d2.post_terminal_receipt",
            crate::store::terminal_cancellation_receipt::validate_terminal_cancellation_receipt(
                &reader, receipt,
            ),
        )?;
        super::test_support_diagnostics::on_error(
            "cancel.d2.post_evidence_receipt",
            crate::store::terminal_cancellation_receipt::validate_d2_tool_loop_cancellation_evidence(
                &reader, receipt, evidence,
            ),
        )?;
        Ok(true)
    }

    fn validate_no_admission_cancellation_receipt(
        &self,
        receipt: &runne_application::ports::TextGenerationReceipt,
    ) -> Result<bool, CommitError> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = reader
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let valid =
            super::terminal_cancellation_receipt::validate_no_admission_receipt(&tx, receipt)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        Ok(valid)
    }

    fn lookup_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        self.lookup_text_generation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
        )
    }

    fn lookup_claimed_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
        assignment: &TaskRunAssignmentIdentity,
        claim_version: u64,
    ) -> Result<TextGenerationReceiptLookup, CommitError> {
        self.lookup_claimed_text_generation_receipt_impl(
            command_id,
            idempotency_key,
            idempotency_scope,
            fingerprint,
            assignment,
            claim_version,
        )
    }

    fn begin_text_generation(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.begin_text_generation_impl(payload)
    }

    fn begin_claimed_text_generation(
        &self,
        payload: BeginClaimedTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.begin_claimed_text_generation_impl(payload)
    }

    fn finish_text_generation(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.finish_text_generation_impl(payload)
    }

    fn reject_text_generation(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_impl(payload)
    }

    fn reject_text_generation_after_d2_tool_loop_restart(
        &self,
        payload: runne_application::ports::RejectTextGenerationAfterD2ToolLoopRestartCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_d2_tool_loop_restart_impl(payload)
    }

    fn reject_text_generation_after_terminal_cancellation(
        &self,
        payload: RejectTextGenerationAfterTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_terminal_cancellation_impl(payload)
    }

    fn reject_text_generation_after_unknown_terminal_cancellation(
        &self,
        payload: RejectTextGenerationAfterUnknownTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_unknown_terminal_cancellation_impl(payload)
    }

    fn reject_text_generation_after_remote_artifact_cancellation(
        &self,
        payload: runne_application::ports::RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_remote_artifact_cancellation_impl(payload)
    }

    fn reject_text_generation_after_pre_effect_cancellation(
        &self,
        payload: RejectTextGenerationAfterPreEffectCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_pre_effect_cancellation_impl(payload)
    }

    fn reject_text_generation_after_no_admission_cancellation(
        &self,
        payload: runne_application::ports::RejectTextGenerationAfterNoAdmissionCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_no_admission_cancellation_impl(payload)
    }

    fn reject_text_generation_after_d2_tool_loop_cancellation(
        &self,
        payload: runne_application::ports::RejectTextGenerationAfterD2ToolLoopCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_cancellation_impl(
            runne_application::ports::RejectTextGenerationAfterCancellationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_started_taskrun_version: payload.expected_started_taskrun_version,
                proof: runne_application::ports::ProviderCancellationProof::D2ToolLoop(
                    payload.evidence,
                ),
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
        )
    }
}
