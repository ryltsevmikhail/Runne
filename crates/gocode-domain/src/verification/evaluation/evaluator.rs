// ===== Deterministic Evaluator =====

/// Pure deterministic evaluator — no I/O, no side effects.
pub struct DeterministicEvaluator;

impl DeterministicEvaluator {
    /// Evaluate a single gate: check evidence layer requirements and criteria.
    /// Pure function: same inputs → same output.
    pub fn evaluate_gate(
        required_layers: &[String],
        evidence_layers: &[String],
        criteria_met: bool,
    ) -> GateResult {
        // Check all required layers are present in evidence
        for required in required_layers {
            if !evidence_layers.contains(required) {
                return GateResult::Blocked;
            }
        }
        if criteria_met {
            GateResult::Passed
        } else {
            GateResult::Failed
        }
    }

    /// Aggregate gate evaluations into plan result.
    pub fn evaluate_plan(gate_results: &[(String, GateResult)]) -> PlanResult {
        aggregate_plan_result(gate_results)
    }
}

// ===== Statistical Policy =====

/// Predeclared statistical evaluation policy (L4 only).
#[derive(Clone, Debug)]
pub struct StatisticalPolicy {
    pub sample_size: u64,
    pub margin: f64,
    pub confidence: f64,
}

/// Statistical evaluation result — consumed by GateEvaluator.
#[derive(Clone, Debug)]
pub struct StatisticalResult {
    pub sample_size_achieved: u64,
    pub sufficient: bool,
    pub metric_value: f64,
}

impl StatisticalResult {
    pub fn evaluate(policy: &StatisticalPolicy, samples: &[f64]) -> Self {
        let achieved = samples.len() as u64;
        let sufficient = achieved >= policy.sample_size;
        let metric_value = if achieved > 0 {
            samples.iter().sum::<f64>() / achieved as f64
        } else {
            0.0
        };
        Self {
            sample_size_achieved: achieved,
            sufficient,
            metric_value,
        }
    }
}
