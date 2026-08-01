/// Result of a single scenario execution.
#[derive(Clone, Debug)]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub passed: bool,
    pub evidence: EvidenceItem,
}
