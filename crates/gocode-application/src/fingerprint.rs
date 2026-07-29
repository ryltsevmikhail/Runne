//! Command fingerprint — SHA-256 canonical encoding for idempotency.
//!
//! Each use case has a typed constructor that produces a deterministic
//! 32-byte digest. The encoding includes:
//!   - Domain-separation prefix `gocode-cmd\x01`
//!   - Schema version (u16, BE)
//!   - Operation tag (u8)
//!   - Length-prefixed semantic fields (u16 BE lengths)
//!   - Raw UUID bytes (16 bytes each)
//!   - TerminalResult canonical encoding (for complete only)
//!
//! Server-generated IDs (TaskRunId/AttemptId/EventId/CommandId) are
//! deliberately **not** included — a retry must return the original IDs.

use gocode_domain::agent_loop::{
    LoopDisposition, StepOutcomeRecord, StepOutcomeType, WakeCondition, WakeEvidenceRef,
    WakeEvidenceSource,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::context::ContextManifestRef;
use gocode_domain::id::{ConversationId, IntegrityDigest, TaskRunId, WorkspaceId};
use gocode_domain::plan::PlanRevisionRef;
use gocode_domain::recovery::ReconciliationResultRef;
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use sha2::{Digest, Sha256};

pub use gocode_api::MAX_CANONICAL_TERMINAL_REASON_BYTES as MAX_TERMINAL_REASON_BYTES;

use crate::commands::{
    ActivateScheduledRetryInput, CommitContextInput, CommitLoopCheckpointInput, CommitPlanInput,
    CommitRecoveryResumeInput, CompleteLoopCycleInput, CreateNextCycleInput,
    RecordStepOutcomeInput, ResumeLoopWaitInput, ScheduleRetryInput, StartLoopCycleInput,
};
use crate::errors::FingerprintError;

/// Domain-separation prefix for command fingerprints.
const DOMAIN_PREFIX: &[u8] = b"gocode-cmd\x01";

/// Current schema version for fingerprint encoding.
const SCHEMA_VERSION: u16 = 1;

/// Operation tags (must match [`crate::ports::OperationTag`]).
const TAG_CREATE: u8 = 1;
const TAG_QUEUE: u8 = 2;
const TAG_ADMIT: u8 = 3;
const TAG_START_ATTEMPT: u8 = 4;
const TAG_COMPLETE: u8 = 5;
const TAG_CREATE_CONVERSATION: u8 = 6;
const TAG_START_LOOP_CYCLE: u8 = 7;
const TAG_COMMIT_CONTEXT: u8 = 8;
const TAG_COMMIT_PLAN: u8 = 9;
const TAG_RECORD_STEP_OUTCOME: u8 = 10;
const TAG_COMPLETE_LOOP_CYCLE: u8 = 11;
const TAG_CREATE_NEXT_CYCLE: u8 = 12;
const TAG_SCHEDULE_RETRY: u8 = 13;
const TAG_ACTIVATE_RETRY: u8 = 14;
const TAG_COMMIT_RECOVERY_RESUME: u8 = 15;
const TAG_COMMIT_LOOP_CHECKPOINT: u8 = 16;
const TAG_RESUME_LOOP_WAIT: u8 = 17;
const CHECKPOINT_BODY_PREFIX: &[u8] = b"gocode-loop-checkpoint-body\x01";

fn begin(tag: u8) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PREFIX);
    hasher.update(SCHEMA_VERSION.to_be_bytes());
    hasher.update([tag]);
    hasher
}

fn update_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn update_context_ref(hasher: &mut Sha256, value: &ContextManifestRef) {
    hasher.update(value.manifest_id.as_bytes());
    hasher.update(value.taskrun_id.as_bytes());
    hasher.update(value.attempt_id.as_bytes());
    hasher.update(value.cycle_id.as_bytes());
    hasher.update(value.revision.to_be_bytes());
    update_string(hasher, &value.policy_revision);
    hasher.update(value.integrity_digest.as_bytes());
}

fn update_result_ref(hasher: &mut Sha256, value: &ResultRef) {
    hasher.update(value.result_id.as_bytes());
    update_string(hasher, &value.media_type);
    hasher.update(value.integrity_digest.as_bytes());
}

fn update_budget_ref(hasher: &mut Sha256, value: &BudgetReservationRef) {
    hasher.update(value.reservation_id.as_bytes());
    hasher.update(value.taskrun_id.as_bytes());
    hasher.update(value.attempt_id.as_bytes());
    hasher.update(value.retry_ordinal.to_be_bytes());
    hasher.update(value.reservation_digest.as_bytes());
}

fn update_plan_ref(hasher: &mut Sha256, value: &PlanRevisionRef) {
    hasher.update(value.plan_id.as_bytes());
    hasher.update(value.taskrun_id.as_bytes());
    hasher.update(value.cycle_id.as_bytes());
    hasher.update(value.revision.to_be_bytes());
    update_context_ref(hasher, &value.context_manifest_ref);
    hasher.update((value.expected_proposal_indexes.len() as u64).to_be_bytes());
    for index in &value.expected_proposal_indexes {
        hasher.update(index.to_be_bytes());
    }
    hasher.update(value.proposal_batch_digest.as_bytes());
    update_result_ref(hasher, &value.planning_policy_ref);
    update_budget_ref(hasher, &value.planning_budget_ref);
    match &value.parent_ref {
        None => hasher.update([0]),
        Some(parent) => {
            hasher.update([1]);
            hasher.update(parent.plan_id.as_bytes());
            hasher.update(parent.revision.to_be_bytes());
            hasher.update(parent.integrity_digest.as_bytes());
        }
    }
    hasher.update(value.integrity_digest.as_bytes());
}

fn update_step_ref(hasher: &mut Sha256, value: &gocode_domain::agent_loop::StepOutcomeRef) {
    hasher.update(value.cycle_id.as_bytes());
    hasher.update(value.proposal_index.to_be_bytes());
    hasher.update(value.step_id.as_bytes());
    hasher.update(value.outcome_digest.as_bytes());
}

fn update_step_record(hasher: &mut Sha256, value: &StepOutcomeRecord) {
    hasher.update(value.proposal_index.to_be_bytes());
    hasher.update(value.step_id.as_bytes());
    hasher.update([match value.outcome_type {
        StepOutcomeType::Succeeded => 0,
        StepOutcomeType::FailedBeforeCommit => 1,
        StepOutcomeType::FailedAfterCommit => 2,
        StepOutcomeType::Uncertain => 3,
        StepOutcomeType::Cancelled => 4,
    }]);
    match &value.result_ref {
        None => hasher.update([0]),
        Some(result) => {
            hasher.update([1]);
            update_result_ref(hasher, result);
        }
    }
    match value.effect_id {
        None => hasher.update([0]),
        Some(effect_id) => {
            hasher.update([1]);
            hasher.update(effect_id.as_bytes());
        }
    }
    hasher.update((value.evidence_digests.len() as u64).to_be_bytes());
    for digest in &value.evidence_digests {
        hasher.update(digest.as_bytes());
    }
}

fn update_wake_condition(hasher: &mut Sha256, value: &WakeCondition) {
    hasher.update([value.kind as u8]);
    update_string(hasher, &value.condition_ref);
    hasher.update(value.condition_digest.as_bytes());
}

fn update_wake_evidence(hasher: &mut Sha256, value: &WakeEvidenceRef) {
    hasher.update(value.cycle_id.as_bytes());
    hasher.update(value.condition_digest.as_bytes());
    hasher.update([match value.source {
        WakeEvidenceSource::ExternalInput => 0,
        WakeEvidenceSource::Approval => 1,
        WakeEvidenceSource::ChildTaskRun => 2,
        WakeEvidenceSource::Timer => 3,
        WakeEvidenceSource::Reconciliation => 4,
    }]);
    hasher.update(value.evidence_id.as_bytes());
    hasher.update(value.evidence_digest.as_bytes());
    hasher.update(value.observed_at_unix_us.to_be_bytes());
    update_string(hasher, &value.authority_revision);
}

fn update_disposition(hasher: &mut Sha256, value: &LoopDisposition) {
    match value {
        LoopDisposition::Continue => hasher.update([0]),
        LoopDisposition::Wait {
            reason,
            wake_condition,
        } => {
            hasher.update([1]);
            update_string(hasher, reason);
            update_wake_condition(hasher, wake_condition);
        }
        LoopDisposition::Complete {
            plan_evaluation_ref,
        } => {
            hasher.update([2]);
            hasher.update(plan_evaluation_ref.evaluation_id.as_bytes());
            hasher.update(plan_evaluation_ref.taskrun_id.as_bytes());
            hasher.update(plan_evaluation_ref.plan_id.as_bytes());
            hasher.update(plan_evaluation_ref.plan_revision.to_be_bytes());
            hasher.update(plan_evaluation_ref.evaluated_stream_head.to_be_bytes());
            hasher.update([plan_evaluation_ref.result as u8]);
            hasher.update(plan_evaluation_ref.gate_definitions_digest.as_bytes());
            hasher.update(plan_evaluation_ref.evidence_set_digest.as_bytes());
            hasher.update(plan_evaluation_ref.evaluation_digest.as_bytes());
        }
        LoopDisposition::Fail {
            reason,
            unresolved_proposals,
        } => {
            hasher.update([3]);
            update_string(hasher, reason);
            hasher.update((unresolved_proposals.len() as u64).to_be_bytes());
            for index in unresolved_proposals {
                hasher.update(index.to_be_bytes());
            }
        }
    }
}

fn update_checkpoint_ref(hasher: &mut Sha256, value: &CheckpointRef) {
    hasher.update(value.checkpoint_id.as_bytes());
    hasher.update(value.event_position.to_be_bytes());
    hasher.update(value.integrity_digest.as_bytes());
}

fn update_reconciliation_ref(hasher: &mut Sha256, value: &ReconciliationResultRef) {
    hasher.update(value.reconciliation_run_id.as_bytes());
    hasher.update(value.taskrun_id.as_bytes());
    hasher.update(value.predecessor_attempt_id.as_bytes());
    hasher.update(value.recovery_generation.to_be_bytes());
    hasher.update(value.reconciled_stream_position.to_be_bytes());
    hasher.update([value.status as u8]);
    hasher.update(value.unresolved_effect_count.to_be_bytes());
    hasher.update(value.result_digest.as_bytes());
}

pub fn checkpoint_body_digest(input: &CommitLoopCheckpointInput) -> IntegrityDigest {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_BODY_PREFIX);
    hasher.update(input.cycle_id.as_bytes());
    hasher.update(input.attempt_id.as_bytes());
    update_string(&mut hasher, &input.schema_version);
    match &input.plan_revision_ref {
        None => hasher.update([0]),
        Some(plan_ref) => {
            hasher.update([1]);
            update_plan_ref(&mut hasher, plan_ref);
        }
    }
    match &input.context_manifest_ref {
        None => hasher.update([0]),
        Some(context_ref) => {
            hasher.update([1]);
            update_context_ref(&mut hasher, context_ref);
        }
    }
    hasher.update((input.step_outcome_refs.len() as u64).to_be_bytes());
    for step_ref in &input.step_outcome_refs {
        update_step_ref(&mut hasher, step_ref);
    }
    IntegrityDigest::from_bytes(hasher.finalize().into())
}

/// A SHA-256 fingerprint of a command's semantic payload.
///
/// Used for idempotency: two commands with the same scope, key, and
/// fingerprint are considered identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandFingerprint([u8; 32]);

impl CommandFingerprint {
    /// Create from raw 32-byte digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw 32-byte digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return the raw 32-byte digest.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Create a fingerprint for `CreateTaskRun`.
    ///
    /// The fingerprint includes only the conversation and workspace IDs
    /// (not the server-generated `TaskRunId`).
    pub fn for_create(conversation_id: &ConversationId, workspace_id: &WorkspaceId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_CREATE]);
        // conversation_id: 16 raw bytes
        hasher.update(conversation_id.as_bytes());
        // workspace_id: 16 raw bytes
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `CreateConversation`.
    pub fn for_create_conversation(
        conversation_id: &ConversationId,
        workspace_id: &WorkspaceId,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_CREATE_CONVERSATION]);
        hasher.update(conversation_id.as_bytes());
        hasher.update(workspace_id.as_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Queue`.
    pub fn for_queue(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_QUEUE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Admit`.
    pub fn for_admit(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_ADMIT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `StartAttempt`.
    pub fn for_start_attempt(taskrun_id: &TaskRunId, expected_version: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_START_ATTEMPT]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Create a fingerprint for `Complete`.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintError::TerminalReasonTooLong`] if the
    /// `TerminalResult::Failure.reason` exceeds
    /// [`MAX_TERMINAL_REASON_BYTES`].
    pub fn for_complete(
        taskrun_id: &TaskRunId,
        result: &TerminalResult,
        expected_version: u64,
    ) -> Result<Self, FingerprintError> {
        // Validate reason length for Failure
        if let TerminalResult::Failure { reason } = result {
            let len = reason.len();
            if len > MAX_TERMINAL_REASON_BYTES {
                return Err(FingerprintError::TerminalReasonTooLong {
                    max: MAX_TERMINAL_REASON_BYTES,
                    actual: len,
                });
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_PREFIX);
        hasher.update(SCHEMA_VERSION.to_be_bytes());
        hasher.update([TAG_COMPLETE]);
        // taskrun_id: 16 raw bytes
        hasher.update(taskrun_id.as_bytes());
        // expected_version: 8 bytes BE
        hasher.update(expected_version.to_be_bytes());
        // TerminalResult canonical encoding:
        //   tag: 0x00 = Success, 0x01 = Failure
        //   for Failure: reason_len (u16 BE) || reason_bytes
        match result {
            TerminalResult::Success => {
                hasher.update([0x00u8]);
            }
            TerminalResult::Failure { reason } => {
                hasher.update([0x01u8]);
                let reason_bytes = reason.as_bytes();
                hasher.update((reason_bytes.len() as u16).to_be_bytes());
                hasher.update(reason_bytes);
            }
        }
        Ok(Self(hasher.finalize().into()))
    }

    pub fn for_start_loop_cycle(input: &StartLoopCycleInput) -> Self {
        let mut hasher = begin(TAG_START_LOOP_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_commit_context(input: &CommitContextInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_CONTEXT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_context_ref(&mut hasher, &input.manifest_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_commit_plan(input: &CommitPlanInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_PLAN);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_plan_ref(&mut hasher, &input.plan_revision_ref);
        hasher.update(input.input_digest.as_bytes());
        hasher.update(input.output_digest.as_bytes());
        hasher.update((input.expected_proposal_indexes.len() as u64).to_be_bytes());
        for index in &input.expected_proposal_indexes {
            hasher.update(index.to_be_bytes());
        }
        Self(hasher.finalize().into())
    }

    pub fn for_record_step_outcome(input: &RecordStepOutcomeInput) -> Self {
        let mut hasher = begin(TAG_RECORD_STEP_OUTCOME);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_step_record(&mut hasher, &input.outcome);
        Self(hasher.finalize().into())
    }

    pub fn for_complete_loop_cycle(input: &CompleteLoopCycleInput) -> Self {
        let mut hasher = begin(TAG_COMPLETE_LOOP_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        update_disposition(&mut hasher, &input.disposition);
        Self(hasher.finalize().into())
    }

    pub fn for_create_next_cycle(input: &CreateNextCycleInput) -> Self {
        let mut hasher = begin(TAG_CREATE_NEXT_CYCLE);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.parent_cycle_id.as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_resume_loop_wait(input: &ResumeLoopWaitInput) -> Self {
        let mut hasher = begin(TAG_RESUME_LOOP_WAIT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        update_wake_evidence(&mut hasher, &input.wake_evidence_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_schedule_retry(input: &ScheduleRetryInput) -> Self {
        let mut hasher = begin(TAG_SCHEDULE_RETRY);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.retry_ordinal.to_be_bytes());
        update_step_ref(&mut hasher, &input.step_outcome_ref);
        hasher.update(input.retry_policy_digest.as_bytes());
        update_budget_ref(&mut hasher, &input.budget_reservation_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_activate_retry(input: &ActivateScheduledRetryInput) -> Self {
        let mut hasher = begin(TAG_ACTIVATE_RETRY);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.retry_ordinal.to_be_bytes());
        Self(hasher.finalize().into())
    }

    pub fn for_commit_recovery_resume(input: &CommitRecoveryResumeInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_RECOVERY_RESUME);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        update_context_ref(&mut hasher, &input.context_manifest_ref);
        update_checkpoint_ref(&mut hasher, &input.checkpoint_ref);
        update_reconciliation_ref(&mut hasher, &input.reconciliation_ref);
        Self(hasher.finalize().into())
    }

    pub fn for_commit_loop_checkpoint(input: &CommitLoopCheckpointInput) -> Self {
        let mut hasher = begin(TAG_COMMIT_LOOP_CHECKPOINT);
        hasher.update(input.taskrun_id.as_bytes());
        hasher.update(input.expected_version.to_be_bytes());
        hasher.update(input.cycle_id.as_bytes());
        hasher.update(input.attempt_id.as_bytes());
        update_string(&mut hasher, &input.schema_version);
        match &input.plan_revision_ref {
            None => hasher.update([0]),
            Some(plan_ref) => {
                hasher.update([1]);
                update_plan_ref(&mut hasher, plan_ref);
            }
        }
        match &input.context_manifest_ref {
            None => hasher.update([0]),
            Some(context_ref) => {
                hasher.update([1]);
                update_context_ref(&mut hasher, context_ref);
            }
        }
        hasher.update((input.step_outcome_refs.len() as u64).to_be_bytes());
        for step_ref in &input.step_outcome_refs {
            update_step_ref(&mut hasher, step_ref);
        }
        Self(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONV_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000001";
    const WS_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000002";
    const TR_ID_STR: &str = "018f2e3a-7000-7000-8000-000000000003";

    #[test]
    fn test_for_create_deterministic() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv_id, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv_id, &ws_id);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.as_bytes(), fp2.as_bytes());
    }

    #[test]
    fn test_for_create_different_conv_is_different() {
        let conv1: ConversationId = CONV_ID_STR.parse().unwrap();
        let conv2: ConversationId = "018f2e3a-7000-7000-8000-00000000000a".parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_create(&conv1, &ws_id);
        let fp2 = CommandFingerprint::for_create(&conv2, &ws_id);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn create_conversation_has_a_distinct_deterministic_domain() {
        let conversation_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let workspace_id: WorkspaceId = WS_ID_STR.parse().unwrap();

        let first = CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id);
        let second = CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id);

        assert_eq!(first, second);
        assert_ne!(
            first,
            CommandFingerprint::for_create(&conversation_id, &workspace_id)
        );
    }

    #[test]
    fn test_for_queue_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_queue_different_version_is_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_for_admit_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 1);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_start_attempt_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Success;
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_failure_deterministic() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let result = TerminalResult::Failure {
            reason: "test failure".into(),
        };
        let fp1 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_for_complete_success_vs_failure_different() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_success =
            CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 3).unwrap();
        let fp_failure = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: "err".into(),
            },
            3,
        )
        .unwrap();
        assert_ne!(fp_success, fp_failure);
    }

    #[test]
    fn test_for_complete_reason_too_long() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let long_reason = "x".repeat(MAX_TERMINAL_REASON_BYTES + 1);
        let result = TerminalResult::Failure {
            reason: long_reason.clone(),
        };
        let err = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap_err();
        assert_eq!(
            err,
            FingerprintError::TerminalReasonTooLong {
                max: MAX_TERMINAL_REASON_BYTES,
                actual: long_reason.len(),
            }
        );
    }

    #[test]
    fn test_for_complete_reason_at_limit_ok() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let reason = "x".repeat(MAX_TERMINAL_REASON_BYTES);
        let result = TerminalResult::Failure {
            reason: reason.clone(),
        };
        let fp = CommandFingerprint::for_complete(&tr_id, &result, 3).unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn phase5_semantic_fingerprint_matrix() {
        let taskrun_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let cycle_id = CONV_ID_STR.parse().unwrap();
        let start = StartLoopCycleInput {
            taskrun_id,
            expected_version: 7,
        };
        assert_eq!(
            CommandFingerprint::for_start_loop_cycle(&start),
            CommandFingerprint::for_start_loop_cycle(&start)
        );
        assert_ne!(
            CommandFingerprint::for_start_loop_cycle(&start),
            CommandFingerprint::for_start_loop_cycle(&StartLoopCycleInput {
                expected_version: 8,
                ..start.clone()
            })
        );

        let fail = CompleteLoopCycleInput {
            taskrun_id,
            expected_version: 9,
            cycle_id,
            disposition: LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![1],
            },
        };
        let changed_unresolved = CompleteLoopCycleInput {
            disposition: LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![2],
            },
            ..fail.clone()
        };
        assert_ne!(
            CommandFingerprint::for_complete_loop_cycle(&fail),
            CommandFingerprint::for_complete_loop_cycle(&changed_unresolved)
        );

        let wake = ResumeLoopWaitInput {
            taskrun_id,
            expected_version: 10,
            wake_evidence_ref: WakeEvidenceRef {
                cycle_id,
                condition_digest: gocode_domain::id::IntegrityDigest::from_bytes([1; 32]),
                source: WakeEvidenceSource::Approval,
                evidence_id: WS_ID_STR.parse().unwrap(),
                evidence_digest: gocode_domain::id::IntegrityDigest::from_bytes([2; 32]),
                observed_at_unix_us: 11,
                authority_revision: "approval-v1".into(),
            },
        };
        let mut changed_wake = wake.clone();
        changed_wake.wake_evidence_ref.evidence_digest =
            gocode_domain::id::IntegrityDigest::from_bytes([3; 32]);
        assert_ne!(
            CommandFingerprint::for_resume_loop_wait(&wake),
            CommandFingerprint::for_resume_loop_wait(&changed_wake)
        );
    }

    // ── Golden vectors ────────────────────────────────────────────────────

    #[test]
    fn test_golden_for_create() {
        let conv_id: ConversationId = CONV_ID_STR.parse().unwrap();
        let ws_id: WorkspaceId = WS_ID_STR.parse().unwrap();
        let fp = CommandFingerprint::for_create(&conv_id, &ws_id);
        // Pre-computed SHA-256 of:
        //   domain_prefix(12) || schema_version(2,BE=0x0001) || tag(0x01) ||
        //   conv_id(16) || ws_id(16)
        let expected: [u8; 32] = [
            0xb8, 0x1d, 0x69, 0x9a, 0x32, 0xef, 0x6d, 0xcc, 0x42, 0xb3, 0x49, 0xb2, 0x3d, 0x39,
            0x1b, 0xa8, 0x12, 0xc6, 0x43, 0x5e, 0x1b, 0x95, 0x6e, 0xf6, 0x84, 0xac, 0xf9, 0x66,
            0x7b, 0x05, 0xea, 0x88,
        ];
        assert_eq!(*fp.as_bytes(), expected);
    }

    #[test]
    fn test_golden_for_queue() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_queue(&tr_id, 0);
        let fp2 = CommandFingerprint::for_queue(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_queue(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_admit() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_admit(&tr_id, 0);
        let fp2 = CommandFingerprint::for_admit(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_admit(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_start_attempt() {
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        let fp2 = CommandFingerprint::for_start_attempt(&tr_id, 0);
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_start_attempt(&tr_id, 1);
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_success() {
        use gocode_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        let fp2 = CommandFingerprint::for_complete(&tr_id, &TerminalResult::Success, 0).unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("x"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_for_complete_failure() {
        use gocode_domain::command::TerminalResult;
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp1 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        let fp2 = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("ERR"),
            },
            0,
        )
        .unwrap();
        assert_eq!(fp1, fp2);

        let fp_diff = CommandFingerprint::for_complete(
            &tr_id,
            &TerminalResult::Failure {
                reason: String::from("OTHER"),
            },
            0,
        )
        .unwrap();
        assert_ne!(fp1, fp_diff);
    }

    #[test]
    fn test_golden_tags_are_distinct() {
        // Same inputs, different tags → different digests
        let tr_id: TaskRunId = TR_ID_STR.parse().unwrap();
        let fp_queue = CommandFingerprint::for_queue(&tr_id, 0);
        let fp_admit = CommandFingerprint::for_admit(&tr_id, 0);
        assert_ne!(fp_queue, fp_admit);
    }
}
