use super::taskrun_types::*;
use std::fmt;

macro_rules! copy_getters { ($type:ty: $($method:ident => $field:ident : $return:ty),+ $(,)?) => { impl $type { $(pub const fn $method(&self) -> $return { self.$field })+ } }; }
macro_rules! ref_getters { ($type:ty: $($method:ident => $field:ident : $return:ty),+ $(,)?) => { impl $type { $(pub fn $method(&self) -> $return { &self.$field })+ } }; }
copy_getters!(TaskRunActiveCycleV1: cycle_id=>cycle_id:[u8;16], attempt_id=>attempt_id:[u8;16], sequence=>sequence:u64, parent_cycle_id=>parent_cycle_id:Option<[u8;16]>, state=>state:TaskRunLoopStateV1);
ref_getters!(TaskRunActiveCycleV1: expected_indexes=>expected_indexes:&[u32], outcomes=>outcomes:&[TaskRunOutcomeV1]);
impl TaskRunActiveCycleV1 {
    pub fn context(&self) -> Option<&TaskRunContextRefV1> {
        self.context.as_ref()
    }
    pub fn plan(&self) -> Option<&TaskRunPlanRefV1> {
        self.plan.as_ref()
    }
}
copy_getters!(TaskRunContextRefV1: manifest_id=>manifest_id:[u8;16], taskrun_id=>taskrun_id:[u8;16], attempt_id=>attempt_id:[u8;16], cycle_id=>cycle_id:[u8;16], revision=>revision:u64, integrity_digest=>integrity_digest:[u8;32]);
impl TaskRunContextRefV1 {
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
}
copy_getters!(TaskRunPlanRefV1: plan_id=>plan_id:[u8;16], taskrun_id=>taskrun_id:[u8;16], cycle_id=>cycle_id:[u8;16], revision=>revision:u64, proposal_batch_digest=>proposal_batch_digest:[u8;32], integrity_digest=>integrity_digest:[u8;32]);
ref_getters!(TaskRunPlanRefV1: context=>context:&TaskRunContextRefV1, expected_indexes=>expected_indexes:&[u32], policy=>policy:&TaskRunResultRefV1, budget=>budget:&TaskRunBudgetRefV1);
impl TaskRunPlanRefV1 {
    pub fn parent(&self) -> Option<&TaskRunPlanParentV1> {
        self.parent.as_ref()
    }
}
copy_getters!(TaskRunPlanParentV1: plan_id=>plan_id:[u8;16], revision=>revision:u64, integrity_digest=>integrity_digest:[u8;32]);
copy_getters!(TaskRunResultRefV1: result_id=>result_id:[u8;16], integrity_digest=>integrity_digest:[u8;32]);
impl TaskRunResultRefV1 {
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}
copy_getters!(TaskRunBudgetRefV1: reservation_id=>reservation_id:[u8;16], taskrun_id=>taskrun_id:[u8;16], attempt_id=>attempt_id:[u8;16], retry_ordinal=>retry_ordinal:u64, reservation_digest=>reservation_digest:[u8;32]);
copy_getters!(TaskRunOutcomeV1: proposal_index=>proposal_index:u32, step_id=>step_id:[u8;16], outcome=>outcome:TaskRunOutcomeKindV1, effect_id=>effect_id:Option<[u8;16]>);
ref_getters!(TaskRunOutcomeV1: evidence_digests=>evidence_digests:&[[u8;32]]);
impl TaskRunOutcomeV1 {
    pub fn result(&self) -> Option<&TaskRunResultRefV1> {
        self.result.as_ref()
    }
}
copy_getters!(TaskRunCompletedCycleV1: cycle_id=>cycle_id:[u8;16], attempt_id=>attempt_id:[u8;16], sequence=>sequence:u64, successor_allocated=>successor_allocated:bool);
ref_getters!(TaskRunCompletedCycleV1: disposition=>disposition:&TaskRunDispositionV1);
impl TaskRunCompletedCycleV1 {
    pub fn accepted_wake_evidence(&self) -> Option<&TaskRunWakeEvidenceV1> {
        self.accepted_wake_evidence.as_ref()
    }
}
copy_getters!(TaskRunWakeV1: kind=>kind:TaskRunWakeKindV1, condition_digest=>condition_digest:[u8;32]);
impl TaskRunWakeV1 {
    pub fn condition_ref(&self) -> &str {
        &self.condition_ref
    }
}
copy_getters!(TaskRunWakeEvidenceV1: cycle_id=>cycle_id:[u8;16], condition_digest=>condition_digest:[u8;32], source=>source:TaskRunWakeKindV1, evidence_id=>evidence_id:[u8;16], evidence_digest=>evidence_digest:[u8;32], observed_at_unix_us=>observed_at_unix_us:i64);
impl TaskRunWakeEvidenceV1 {
    pub fn authority_revision(&self) -> &str {
        &self.authority_revision
    }
}
copy_getters!(TaskRunEvaluationV1: evaluation_id=>evaluation_id:[u8;16], taskrun_id=>taskrun_id:[u8;16], plan_id=>plan_id:[u8;16], plan_revision=>plan_revision:u64, evaluated_stream_head=>evaluated_stream_head:u64, result=>result:TaskRunEvaluationResultV1, gate_definitions_digest=>gate_definitions_digest:[u8;32], evidence_set_digest=>evidence_set_digest:[u8;32], evaluation_digest=>evaluation_digest:[u8;32]);
copy_getters!(TaskRunSuccessorV1: parent_cycle_id=>parent_cycle_id:[u8;16], successor_cycle_id=>successor_cycle_id:[u8;16], attempt_id=>attempt_id:[u8;16], sequence=>sequence:u64);
copy_getters!(TaskRunWaitV1: cycle_id=>cycle_id:[u8;16]);
ref_getters!(TaskRunWaitV1: wake=>wake:&TaskRunWakeV1);
copy_getters!(TaskRunRetryV1: ordinal=>ordinal:u64, old_attempt_id=>old_attempt_id:[u8;16], new_attempt_id=>new_attempt_id:[u8;16], abandoned_cycle_id=>abandoned_cycle_id:[u8;16], due_at_unix_us=>due_at_unix_us:i64, delay_ms=>delay_ms:u64, retry_policy_digest=>retry_policy_digest:[u8;32]);
ref_getters!(TaskRunRetryV1: outcome=>outcome:&TaskRunOutcomeRefV1, budget=>budget:&TaskRunBudgetRefV1);
copy_getters!(TaskRunOutcomeRefV1: cycle_id=>cycle_id:[u8;16], proposal_index=>proposal_index:u32, step_id=>step_id:[u8;16], outcome_digest=>outcome_digest:[u8;32]);
copy_getters!(TaskRunCheckpointV1: checkpoint_id=>checkpoint_id:[u8;16], start_position=>start_position:u64, expected_integrity_digest=>expected_integrity_digest:[u8;32], recorded_integrity_digest=>recorded_integrity_digest:Option<[u8;32]>);
copy_getters!(TaskRunCycleHistoryV1: cycle_id=>cycle_id:[u8;16], attempt_id=>attempt_id:[u8;16], sequence=>sequence:u64, parent_cycle_id=>parent_cycle_id:Option<[u8;16]>);
impl TaskRunTerminalResultV1 {
    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            Self::Success => None,
            Self::Failure { reason } => Some(reason),
        }
    }
}
impl TaskRunDispositionV1 {
    pub fn wait(&self) -> Option<(&str, &TaskRunWakeV1)> {
        match self {
            Self::Wait { reason, wake } => Some((reason, wake)),
            _ => None,
        }
    }
    pub fn evaluation(&self) -> Option<&TaskRunEvaluationV1> {
        match self {
            Self::Complete { evaluation } => Some(evaluation),
            _ => None,
        }
    }
    pub fn failure(&self) -> Option<(&str, &[u32])> {
        match self {
            Self::Fail {
                reason,
                unresolved_indexes,
            } => Some((reason, unresolved_indexes)),
            _ => None,
        }
    }
}

impl fmt::Debug for TaskRunPromotionStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskRunPromotionStateV1")
            .field("lifecycle", &self.lifecycle().as_str())
            .field("redacted", &true)
            .finish()
    }
}
