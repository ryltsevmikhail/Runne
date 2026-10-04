use super::*;
use runne_application::ports::{
    ProviderCancellationProof, RejectTextGenerationAfterCancellationCommit,
    RejectTextGenerationAfterNoAdmissionCancellationCommit,
    RejectTextGenerationAfterPreEffectCancellationCommit,
    RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    RejectTextGenerationAfterTerminalCancellationCommit,
    RejectTextGenerationAfterUnknownTerminalCancellationCommit,
};

impl StoreTransaction {
    pub(in crate::store::text) fn reject_text_generation_after_remote_artifact_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_remote_artifact_cancellation_source(payload)
    }

    pub(in crate::store::text) fn reject_text_generation_after_terminal_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_cancellation_impl(
            RejectTextGenerationAfterCancellationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_started_taskrun_version: payload.expected_started_taskrun_version,
                proof: ProviderCancellationProof::Terminal(payload.evidence),
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
        )
    }

    pub(in crate::store::text) fn reject_text_generation_after_unknown_terminal_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterUnknownTerminalCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_cancellation_impl(
            RejectTextGenerationAfterCancellationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_started_taskrun_version: payload.expected_started_taskrun_version,
                proof: ProviderCancellationProof::UnknownTerminal(payload.evidence),
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
        )
    }

    pub(in crate::store::text) fn reject_text_generation_after_pre_effect_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterPreEffectCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_cancellation_impl(
            RejectTextGenerationAfterCancellationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_started_taskrun_version: payload.expected_started_taskrun_version,
                proof: ProviderCancellationProof::PreEffect(payload.evidence),
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
        )
    }

    pub(in crate::store::text) fn reject_text_generation_after_no_admission_cancellation_impl(
        &self,
        payload: RejectTextGenerationAfterNoAdmissionCancellationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError> {
        self.reject_text_generation_after_cancellation_impl(
            RejectTextGenerationAfterCancellationCommit {
                command_id: payload.command_id,
                idempotency_key: payload.idempotency_key,
                idempotency_scope: payload.idempotency_scope,
                command_fingerprint: payload.command_fingerprint,
                expected_conversation_version: payload.expected_conversation_version,
                expected_started_taskrun_version: payload.expected_started_taskrun_version,
                proof: ProviderCancellationProof::NoAdmission(payload.evidence),
                conversation_events: payload.conversation_events,
                taskrun_events: payload.taskrun_events,
                receipt: payload.receipt,
            },
        )
    }
}
