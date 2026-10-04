/// Domain-separation prefix for command fingerprints.
const DOMAIN_PREFIX: &[u8] = b"gocode-cmd\x01";

/// Current schema version for fingerprint encoding.
const SCHEMA_VERSION: u16 = 1;

/// Operation tags (must match [`crate::ports::OperationTag`], except
/// [`TAG_CREATE_CONVERSATION_V2`], which versions the create-conversation
/// fingerprint format instead of introducing a new operation).
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
const TAG_SUPERSEDE_UNKNOWN_TASK_RUN: u8 = 24;
const TAG_GENERATE_CONVERSATION_TEXT: u8 = 18;
const TAG_CANCEL_TASK_RUN: u8 = 19;
const TAG_SUBMIT_TASK_RUN: u8 = 20;
/// Fingerprint-format version 2 for `CreateConversation`: the
/// security-significant delivery-context scope is part of the semantic
/// identity. [`TAG_CREATE_CONVERSATION`] remains only as the legacy format
/// recognized for exact replays of previously stored receipts.
const TAG_CREATE_CONVERSATION_V2: u8 = 21;
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
    hasher.update(value.result_id().as_bytes());
    update_string(hasher, value.media_type());
    hasher.update(value.integrity_digest().as_bytes());
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

fn update_step_ref(hasher: &mut Sha256, value: &runne_domain::agent_loop::StepOutcomeRef) {
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
