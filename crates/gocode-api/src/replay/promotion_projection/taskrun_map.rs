use gocode_domain::agent_loop::{
    LoopCycleState, LoopDisposition, StepOutcomeType, WakeConditionKind, WakeEvidenceSource,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::task_run::{TaskRunSnapshotV1, TaskRunState};
use gocode_domain::verification::PlanEvaluationResult;

use super::taskrun_ids::{digest, id};
use super::taskrun_types::*;

pub(super) fn state(snapshot: &TaskRunSnapshotV1) -> TaskRunPromotionStateV1 {
    TaskRunPromotionStateV1 {
        lifecycle: lifecycle(snapshot.state()),
        active_attempt: snapshot.active_attempt().map(id),
        attempt_history: snapshot.attempt_history().iter().map(id).collect(),
        terminal_result: snapshot.terminal_result().map(terminal),
        active_cycle: snapshot.active_cycle().map(active_cycle),
        last_completed_cycle: snapshot.last_completed_cycle().map(completed_cycle),
        pending_successor: snapshot.pending_successor().map(|v| TaskRunSuccessorV1 {
            parent_cycle_id: id(v.parent_cycle_id),
            successor_cycle_id: id(v.successor_cycle_id),
            attempt_id: id(v.attempt_id),
            sequence: v.sequence,
        }),
        pending_wait: snapshot.pending_loop_wait().map(|v| TaskRunWaitV1 {
            cycle_id: id(v.cycle_id),
            wake: wake(&v.wake_condition),
        }),
        pending_retry: snapshot.pending_retry().map(|v| TaskRunRetryV1 {
            ordinal: v.ordinal,
            old_attempt_id: id(v.old_attempt_id),
            new_attempt_id: id(v.new_attempt_id),
            abandoned_cycle_id: id(v.abandoned_cycle_id),
            outcome: outcome_ref(&v.step_outcome_ref),
            due_at_unix_us: v.due_at_unix_us,
            delay_ms: v.delay_ms,
            budget: budget(&v.budget_reservation_ref),
            retry_policy_digest: digest(v.retry_policy_digest),
        }),
        pending_checkpoint: snapshot
            .pending_loop_checkpoint()
            .map(|v| TaskRunCheckpointV1 {
                checkpoint_id: id(v.checkpoint_id),
                start_position: v.start_position,
                expected_integrity_digest: digest(v.expected_integrity_digest),
                recorded_integrity_digest: v.recorded_integrity_digest.map(digest),
            }),
        cycle_history: snapshot
            .cycle_history()
            .iter()
            .map(|v| TaskRunCycleHistoryV1 {
                cycle_id: id(v.cycle_id),
                attempt_id: id(v.attempt_id),
                sequence: v.sequence,
                parent_cycle_id: v.parent_cycle_id.map(id),
            })
            .collect(),
        recovery_generation: snapshot.recovery_generation(),
    }
}

fn lifecycle(value: TaskRunState) -> TaskRunLifecycleV1 {
    match value {
        TaskRunState::Created => TaskRunLifecycleV1::Created,
        TaskRunState::Queued => TaskRunLifecycleV1::Queued,
        TaskRunState::Admitted => TaskRunLifecycleV1::Admitted,
        TaskRunState::Running => TaskRunLifecycleV1::Running,
        TaskRunState::Waiting => TaskRunLifecycleV1::Waiting,
        TaskRunState::Retrying => TaskRunLifecycleV1::Retrying,
        TaskRunState::Checkpointing => TaskRunLifecycleV1::Checkpointing,
        TaskRunState::Cancelling => TaskRunLifecycleV1::Cancelling,
        TaskRunState::Reconciling => TaskRunLifecycleV1::Reconciling,
        TaskRunState::Succeeded => TaskRunLifecycleV1::Succeeded,
        TaskRunState::Failed => TaskRunLifecycleV1::Failed,
        TaskRunState::Cancelled => TaskRunLifecycleV1::Cancelled,
        TaskRunState::BudgetExhausted => TaskRunLifecycleV1::BudgetExhausted,
        TaskRunState::PolicyDenied => TaskRunLifecycleV1::PolicyDenied,
        TaskRunState::Unrecoverable => TaskRunLifecycleV1::Unrecoverable,
    }
}
fn terminal(value: &TerminalResult) -> TaskRunTerminalResultV1 {
    match value {
        TerminalResult::Success => TaskRunTerminalResultV1::Success,
        TerminalResult::Failure { reason } => TaskRunTerminalResultV1::Failure {
            reason: reason.clone(),
        },
    }
}
fn active_cycle(v: &gocode_domain::agent_loop::ActiveLoopCycle) -> TaskRunActiveCycleV1 {
    TaskRunActiveCycleV1 {
        cycle_id: id(v.cycle_id),
        attempt_id: id(v.attempt_id),
        sequence: v.sequence,
        parent_cycle_id: v.parent_cycle_id.map(id),
        state: loop_state(v.state),
        context: v.context_manifest_ref.as_ref().map(context),
        plan: v.plan_revision_ref.as_ref().map(plan),
        expected_indexes: v.expected_proposal_indexes.clone(),
        outcomes: v.recorded_outcomes.iter().map(outcome).collect(),
    }
}
fn completed_cycle(v: &gocode_domain::agent_loop::CompletedCycleRef) -> TaskRunCompletedCycleV1 {
    TaskRunCompletedCycleV1 {
        cycle_id: id(v.cycle_id),
        attempt_id: id(v.attempt_id),
        sequence: v.sequence,
        disposition: disposition(&v.disposition),
        accepted_wake_evidence: v.accepted_wake_evidence.as_ref().map(evidence),
        successor_allocated: v.successor_allocated,
    }
}
fn loop_state(v: LoopCycleState) -> TaskRunLoopStateV1 {
    match v {
        LoopCycleState::Observing => TaskRunLoopStateV1::Observing,
        LoopCycleState::Proposing => TaskRunLoopStateV1::Proposing,
        LoopCycleState::Acting => TaskRunLoopStateV1::Acting,
        LoopCycleState::Evaluating => TaskRunLoopStateV1::Evaluating,
        LoopCycleState::Completed => TaskRunLoopStateV1::Completed,
    }
}
fn context(v: &gocode_domain::context::ContextManifestRef) -> TaskRunContextRefV1 {
    TaskRunContextRefV1 {
        manifest_id: id(v.manifest_id),
        taskrun_id: id(v.taskrun_id),
        attempt_id: id(v.attempt_id),
        cycle_id: id(v.cycle_id),
        revision: v.revision,
        policy_revision: v.policy_revision.clone(),
        integrity_digest: digest(v.integrity_digest),
    }
}
fn plan(v: &gocode_domain::plan::PlanRevisionRef) -> TaskRunPlanRefV1 {
    TaskRunPlanRefV1 {
        plan_id: id(v.plan_id),
        taskrun_id: id(v.taskrun_id),
        cycle_id: id(v.cycle_id),
        revision: v.revision,
        context: context(&v.context_manifest_ref),
        expected_indexes: v.expected_proposal_indexes.clone(),
        proposal_batch_digest: digest(v.proposal_batch_digest),
        policy: result(&v.planning_policy_ref),
        budget: budget(&v.planning_budget_ref),
        parent: v.parent_ref.as_ref().map(|p| TaskRunPlanParentV1 {
            plan_id: id(p.plan_id),
            revision: p.revision,
            integrity_digest: digest(p.integrity_digest),
        }),
        integrity_digest: digest(v.integrity_digest),
    }
}
fn result(v: &gocode_domain::reference::ResultRef) -> TaskRunResultRefV1 {
    TaskRunResultRefV1 {
        result_id: id(*v.result_id()),
        media_type: v.media_type().to_owned(),
        integrity_digest: digest(*v.integrity_digest()),
    }
}
fn budget(v: &gocode_domain::reference::BudgetReservationRef) -> TaskRunBudgetRefV1 {
    TaskRunBudgetRefV1 {
        reservation_id: id(v.reservation_id),
        taskrun_id: id(v.taskrun_id),
        attempt_id: id(v.attempt_id),
        retry_ordinal: v.retry_ordinal,
        reservation_digest: digest(v.reservation_digest),
    }
}
fn outcome(v: &gocode_domain::agent_loop::StepOutcomeRecord) -> TaskRunOutcomeV1 {
    TaskRunOutcomeV1 {
        proposal_index: v.proposal_index,
        step_id: id(v.step_id),
        outcome: outcome_kind(v.outcome_type),
        result: v.result_ref.as_ref().map(result),
        effect_id: v.effect_id.map(id),
        evidence_digests: v.evidence_digests.iter().copied().map(digest).collect(),
    }
}
fn outcome_ref(v: &gocode_domain::agent_loop::StepOutcomeRef) -> TaskRunOutcomeRefV1 {
    TaskRunOutcomeRefV1 {
        cycle_id: id(v.cycle_id),
        proposal_index: v.proposal_index,
        step_id: id(v.step_id),
        outcome_digest: digest(v.outcome_digest),
    }
}
fn outcome_kind(v: StepOutcomeType) -> TaskRunOutcomeKindV1 {
    match v {
        StepOutcomeType::Succeeded => TaskRunOutcomeKindV1::Succeeded,
        StepOutcomeType::FailedBeforeCommit => TaskRunOutcomeKindV1::FailedBeforeCommit,
        StepOutcomeType::FailedAfterCommit => TaskRunOutcomeKindV1::FailedAfterCommit,
        StepOutcomeType::Uncertain => TaskRunOutcomeKindV1::Uncertain,
        StepOutcomeType::Cancelled => TaskRunOutcomeKindV1::Cancelled,
    }
}
fn disposition(v: &LoopDisposition) -> TaskRunDispositionV1 {
    match v {
        LoopDisposition::Continue => TaskRunDispositionV1::Continue,
        LoopDisposition::Wait {
            reason,
            wake_condition,
        } => TaskRunDispositionV1::Wait {
            reason: reason.clone(),
            wake: wake(wake_condition),
        },
        LoopDisposition::Complete {
            plan_evaluation_ref,
        } => TaskRunDispositionV1::Complete {
            evaluation: evaluation(plan_evaluation_ref),
        },
        LoopDisposition::Fail {
            reason,
            unresolved_proposals,
        } => TaskRunDispositionV1::Fail {
            reason: reason.clone(),
            unresolved_indexes: unresolved_proposals.clone(),
        },
    }
}
fn wake(v: &gocode_domain::agent_loop::WakeCondition) -> TaskRunWakeV1 {
    TaskRunWakeV1 {
        kind: wake_kind(v.kind),
        condition_ref: v.condition_ref.clone(),
        condition_digest: digest(v.condition_digest),
    }
}
fn evidence(v: &gocode_domain::agent_loop::WakeEvidenceRef) -> TaskRunWakeEvidenceV1 {
    TaskRunWakeEvidenceV1 {
        cycle_id: id(v.cycle_id),
        condition_digest: digest(v.condition_digest),
        source: wake_source(v.source),
        evidence_id: id(v.evidence_id),
        evidence_digest: digest(v.evidence_digest),
        observed_at_unix_us: v.observed_at_unix_us,
        authority_revision: v.authority_revision.clone(),
    }
}
fn wake_kind(v: WakeConditionKind) -> TaskRunWakeKindV1 {
    match v {
        WakeConditionKind::ExternalInput => TaskRunWakeKindV1::ExternalInput,
        WakeConditionKind::Approval => TaskRunWakeKindV1::Approval,
        WakeConditionKind::ChildTaskRun => TaskRunWakeKindV1::ChildTaskRun,
        WakeConditionKind::Timer => TaskRunWakeKindV1::Timer,
        WakeConditionKind::Reconciliation => TaskRunWakeKindV1::Reconciliation,
    }
}
fn wake_source(v: WakeEvidenceSource) -> TaskRunWakeKindV1 {
    match v {
        WakeEvidenceSource::ExternalInput => TaskRunWakeKindV1::ExternalInput,
        WakeEvidenceSource::Approval => TaskRunWakeKindV1::Approval,
        WakeEvidenceSource::ChildTaskRun => TaskRunWakeKindV1::ChildTaskRun,
        WakeEvidenceSource::Timer => TaskRunWakeKindV1::Timer,
        WakeEvidenceSource::Reconciliation => TaskRunWakeKindV1::Reconciliation,
    }
}
fn evaluation(v: &gocode_domain::verification::PlanEvaluationRef) -> TaskRunEvaluationV1 {
    TaskRunEvaluationV1 {
        evaluation_id: id(v.evaluation_id),
        taskrun_id: id(v.taskrun_id),
        plan_id: id(v.plan_id),
        plan_revision: v.plan_revision,
        evaluated_stream_head: v.evaluated_stream_head,
        result: match v.result {
            PlanEvaluationResult::Passed => TaskRunEvaluationResultV1::Passed,
            PlanEvaluationResult::Failed => TaskRunEvaluationResultV1::Failed,
            PlanEvaluationResult::Blocked => TaskRunEvaluationResultV1::Blocked,
            PlanEvaluationResult::RequiresReview => TaskRunEvaluationResultV1::RequiresReview,
        },
        gate_definitions_digest: digest(v.gate_definitions_digest),
        evidence_set_digest: digest(v.evidence_set_digest),
        evaluation_digest: digest(v.evaluation_digest),
    }
}
