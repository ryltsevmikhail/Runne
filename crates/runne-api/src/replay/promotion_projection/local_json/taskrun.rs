use serde_json::{Value, json};

use super::hex;
use crate::replay::promotion_projection::*;

pub(super) fn encode(view: &TaskRunPromotionViewV1) -> Value {
    json!({
        "schemaVersion": 1, "kind": "task_run", "aggregateId": hex(&view.aggregate_id()),
        "state": state(view.semantic_state()), "projectionDigest": hex(view.promotion_digest()),
    })
}

fn state(value: &TaskRunPromotionStateV1) -> Value {
    json!({
        "lifecycle": value.lifecycle.as_str(), "activeAttempt": value.active_attempt.map(|id|hex16(&id)),
        "attemptHistory": value.attempt_history.iter().map(hex16).collect::<Vec<_>>(),
        "terminalResult": terminal(value.terminal_result.as_ref()), "activeCycle": value.active_cycle.as_ref().map(cycle),
        "lastCompletedCycle": value.last_completed_cycle.as_ref().map(completed),
        "pendingSuccessor": value.pending_successor.as_ref().map(successor), "pendingWait": value.pending_wait.as_ref().map(wait),
        "pendingRetry": value.pending_retry.as_ref().map(retry), "pendingCheckpoint": value.pending_checkpoint.as_ref().map(checkpoint),
        "cycleHistory": value.cycle_history.iter().map(history).collect::<Vec<_>>(), "recoveryGeneration": value.recovery_generation,
    })
}

fn terminal(value: Option<&TaskRunTerminalResultV1>) -> Value {
    match value {
        None => Value::Null,
        Some(TaskRunTerminalResultV1::Success) => json!({"kind":"success"}),
        Some(TaskRunTerminalResultV1::Failure { reason }) => {
            json!({"kind":"failure","reason":reason})
        }
    }
}
fn cycle(value: &TaskRunActiveCycleV1) -> Value {
    json!({ "cycleId":hex16(&value.cycle_id), "attemptId":hex16(&value.attempt_id), "sequence":value.sequence, "parentCycleId":value.parent_cycle_id.map(|id|hex16(&id)), "state":loop_state(value.state), "context":value.context.as_ref().map(context), "plan":value.plan.as_ref().map(plan), "expectedIndexes":value.expected_indexes, "outcomes":value.outcomes.iter().map(outcome).collect::<Vec<_>>() })
}
fn context(value: &TaskRunContextRefV1) -> Value {
    json!({ "manifestId":hex16(&value.manifest_id), "taskRunId":hex16(&value.taskrun_id), "attemptId":hex16(&value.attempt_id), "cycleId":hex16(&value.cycle_id), "revision":value.revision, "policyRevision":value.policy_revision, "integrityDigest":hex(&value.integrity_digest) })
}
fn plan(value: &TaskRunPlanRefV1) -> Value {
    json!({ "planId":hex16(&value.plan_id), "taskRunId":hex16(&value.taskrun_id), "cycleId":hex16(&value.cycle_id), "revision":value.revision, "context":context(&value.context), "expectedIndexes":value.expected_indexes, "proposalBatchDigest":hex(&value.proposal_batch_digest), "policy":result(&value.policy), "budget":budget(&value.budget), "parent":value.parent.as_ref().map(parent), "integrityDigest":hex(&value.integrity_digest) })
}
fn parent(value: &TaskRunPlanParentV1) -> Value {
    json!({"planId":hex16(&value.plan_id),"revision":value.revision,"integrityDigest":hex(&value.integrity_digest)})
}
fn result(value: &TaskRunResultRefV1) -> Value {
    json!({"resultId":hex16(&value.result_id),"mediaType":value.media_type,"integrityDigest":hex(&value.integrity_digest)})
}
fn budget(value: &TaskRunBudgetRefV1) -> Value {
    json!({"reservationId":hex16(&value.reservation_id),"taskRunId":hex16(&value.taskrun_id),"attemptId":hex16(&value.attempt_id),"retryOrdinal":value.retry_ordinal,"reservationDigest":hex(&value.reservation_digest)})
}
fn outcome(value: &TaskRunOutcomeV1) -> Value {
    json!({"proposalIndex":value.proposal_index,"stepId":hex16(&value.step_id),"outcome":outcome_kind(value.outcome),"result":value.result.as_ref().map(result),"effectId":value.effect_id.map(|id|hex16(&id)),"evidenceDigests":value.evidence_digests.iter().map(|v|hex(v)).collect::<Vec<_>>()})
}
fn completed(value: &TaskRunCompletedCycleV1) -> Value {
    json!({"cycleId":hex16(&value.cycle_id),"attemptId":hex16(&value.attempt_id),"sequence":value.sequence,"disposition":disposition(&value.disposition),"acceptedWakeEvidence":value.accepted_wake_evidence.as_ref().map(evidence),"successorAllocated":value.successor_allocated})
}
fn disposition(value: &TaskRunDispositionV1) -> Value {
    match value {
        TaskRunDispositionV1::Continue => json!({"kind":"continue"}),
        TaskRunDispositionV1::Wait {
            reason,
            wake: condition,
        } => json!({"kind":"wait","reason":reason,"wake":wake(condition)}),
        TaskRunDispositionV1::Complete { evaluation: result } => {
            json!({"kind":"complete","evaluation":evaluation(result)})
        }
        TaskRunDispositionV1::Fail {
            reason,
            unresolved_indexes,
        } => json!({"kind":"fail","reason":reason,"unresolvedIndexes":unresolved_indexes}),
    }
}
fn wake(value: &TaskRunWakeV1) -> Value {
    json!({"kind":wake_kind(value.kind),"conditionRef":value.condition_ref,"conditionDigest":hex(&value.condition_digest)})
}
fn evidence(value: &TaskRunWakeEvidenceV1) -> Value {
    json!({"cycleId":hex16(&value.cycle_id),"conditionDigest":hex(&value.condition_digest),"source":wake_kind(value.source),"evidenceId":hex16(&value.evidence_id),"evidenceDigest":hex(&value.evidence_digest),"observedAtUnixUs":value.observed_at_unix_us,"authorityRevision":value.authority_revision})
}
fn evaluation(value: &TaskRunEvaluationV1) -> Value {
    json!({"evaluationId":hex16(&value.evaluation_id),"taskRunId":hex16(&value.taskrun_id),"planId":hex16(&value.plan_id),"planRevision":value.plan_revision,"evaluatedStreamHead":value.evaluated_stream_head,"result":evaluation_result(value.result),"gateDefinitionsDigest":hex(&value.gate_definitions_digest),"evidenceSetDigest":hex(&value.evidence_set_digest),"evaluationDigest":hex(&value.evaluation_digest)})
}
fn successor(value: &TaskRunSuccessorV1) -> Value {
    json!({"parentCycleId":hex16(&value.parent_cycle_id),"successorCycleId":hex16(&value.successor_cycle_id),"attemptId":hex16(&value.attempt_id),"sequence":value.sequence})
}
fn wait(value: &TaskRunWaitV1) -> Value {
    json!({"cycleId":hex16(&value.cycle_id),"wake":wake(&value.wake)})
}
fn retry(value: &TaskRunRetryV1) -> Value {
    json!({"ordinal":value.ordinal,"oldAttemptId":hex16(&value.old_attempt_id),"newAttemptId":hex16(&value.new_attempt_id),"abandonedCycleId":hex16(&value.abandoned_cycle_id),"outcome":outcome_ref(&value.outcome),"dueAtUnixUs":value.due_at_unix_us,"delayMs":value.delay_ms,"budget":budget(&value.budget),"retryPolicyDigest":hex(&value.retry_policy_digest)})
}
fn outcome_ref(value: &TaskRunOutcomeRefV1) -> Value {
    json!({"cycleId":hex16(&value.cycle_id),"proposalIndex":value.proposal_index,"stepId":hex16(&value.step_id),"outcomeDigest":hex(&value.outcome_digest)})
}
fn checkpoint(value: &TaskRunCheckpointV1) -> Value {
    json!({"checkpointId":hex16(&value.checkpoint_id),"startPosition":value.start_position,"expectedIntegrityDigest":hex(&value.expected_integrity_digest),"recordedIntegrityDigest":value.recorded_integrity_digest.map(|v|hex(&v))})
}
fn history(value: &TaskRunCycleHistoryV1) -> Value {
    json!({"cycleId":hex16(&value.cycle_id),"attemptId":hex16(&value.attempt_id),"sequence":value.sequence,"parentCycleId":value.parent_cycle_id.map(|id|hex16(&id))})
}
fn hex16(value: &[u8; 16]) -> String {
    hex(value)
}
fn loop_state(value: TaskRunLoopStateV1) -> &'static str {
    match value {
        TaskRunLoopStateV1::Observing => "observing",
        TaskRunLoopStateV1::Proposing => "proposing",
        TaskRunLoopStateV1::Acting => "acting",
        TaskRunLoopStateV1::Evaluating => "evaluating",
        TaskRunLoopStateV1::Completed => "completed",
    }
}
fn outcome_kind(value: TaskRunOutcomeKindV1) -> &'static str {
    match value {
        TaskRunOutcomeKindV1::Succeeded => "succeeded",
        TaskRunOutcomeKindV1::FailedBeforeCommit => "failed_before_commit",
        TaskRunOutcomeKindV1::FailedAfterCommit => "failed_after_commit",
        TaskRunOutcomeKindV1::Uncertain => "uncertain",
        TaskRunOutcomeKindV1::Cancelled => "cancelled",
    }
}
fn wake_kind(value: TaskRunWakeKindV1) -> &'static str {
    match value {
        TaskRunWakeKindV1::ExternalInput => "external_input",
        TaskRunWakeKindV1::Approval => "approval",
        TaskRunWakeKindV1::ChildTaskRun => "child_task_run",
        TaskRunWakeKindV1::Timer => "timer",
        TaskRunWakeKindV1::Reconciliation => "reconciliation",
    }
}
fn evaluation_result(value: TaskRunEvaluationResultV1) -> &'static str {
    match value {
        TaskRunEvaluationResultV1::Passed => "passed",
        TaskRunEvaluationResultV1::Failed => "failed",
        TaskRunEvaluationResultV1::Blocked => "blocked",
        TaskRunEvaluationResultV1::RequiresReview => "requires_review",
    }
}
