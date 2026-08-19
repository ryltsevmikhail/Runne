// GateEvaluator — wires runner results through gate definitions
pub struct GateEvaluator;

impl GateEvaluator {
    /// Evaluate a gate against a set of scenario results.
    pub fn evaluate(
        results: &[ScenarioResult],
        required_layer: &str,
        required_count: usize,
    ) -> GateResult {
        let layer_results: Vec<_> = results
            .iter()
            .filter(|r| {
                let layer = match r.evidence.layer {
                    EvidenceLayer::L0 => "L0",
                    EvidenceLayer::L1 => "L1",
                    EvidenceLayer::L2S => "L2-S",
                    EvidenceLayer::L2I => "L2-I",
                    EvidenceLayer::L3 => "L3",
                    EvidenceLayer::L4 => "L4",
                };
                layer == required_layer
            })
            .collect();

        if layer_results.len() < required_count {
            return GateResult::Blocked;
        }
        if layer_results.iter().all(|r| r.passed) {
            GateResult::Passed
        } else {
            GateResult::Failed
        }
    }
}
