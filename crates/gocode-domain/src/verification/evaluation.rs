use crate::verification::identity::*;
use crate::verification::digest::VerificationDigest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateResult { Passed, Failed, Blocked }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanResult { Passed, Failed, Blocked, RequiresReview }

#[derive(Clone, Debug)]
pub struct GateEvaluationRef {
    pub evaluation_ref_id: GateEvaluationID,
    pub evaluation_digest: VerificationDigest,
    pub generation: GateHeadGeneration,
}

#[derive(Clone, Debug)]
pub struct PlanEvaluationRef {
    pub plan_evaluation_id: PlanEvaluationID,
    pub result_digest: VerificationDigest,
}

/// Aggregate plan result from gate results.
pub fn aggregate_plan_result(gate_results: &[(String, GateResult)]) -> PlanResult {
    let any_failed = gate_results.iter().any(|(_, r)| *r == GateResult::Failed);
    if any_failed { return PlanResult::Failed; }
    let any_blocked = gate_results.iter().any(|(_, r)| *r == GateResult::Blocked);
    if any_blocked { return PlanResult::Blocked; }
    PlanResult::Passed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn all_passed() { assert_eq!(aggregate_plan_result(&[("G1".into(), GateResult::Passed)]), PlanResult::Passed); }
    #[test] fn any_failed() { assert_eq!(aggregate_plan_result(&[("G1".into(), GateResult::Passed), ("G2".into(), GateResult::Failed)]), PlanResult::Failed); }
    #[test] fn any_blocked() { assert_eq!(aggregate_plan_result(&[("G1".into(), GateResult::Passed), ("G2".into(), GateResult::Blocked)]), PlanResult::Blocked); }
    #[test] fn failed_wins_over_blocked() { assert_eq!(aggregate_plan_result(&[("G1".into(), GateResult::Failed), ("G2".into(), GateResult::Blocked)]), PlanResult::Failed); }
}
