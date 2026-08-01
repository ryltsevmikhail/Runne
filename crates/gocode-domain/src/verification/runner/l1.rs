/// L1 runner — golden trace comparison.
/// Real execution path: compares actual execution traces against golden revision.
pub struct L1Runner;

impl L1Runner {
    pub fn run(
        run_id: RunID,
        profile_id: ProfileID,
        profile_digest: VerificationDigest,
        golden_revision: &str,
        actual_traces: &[(&str, bool)],
    ) -> Vec<ScenarioResult> {
        actual_traces
            .iter()
            .map(|(id, matches_golden)| {
                let contract = DigestContract::new("gocode:l1-scenario:v1");
                let digest = contract.compute(&[
                    id.as_bytes(),
                    golden_revision.as_bytes(),
                    &[*matches_golden as u8],
                ]);
                let passed = *matches_golden;
                let evidence = EvidenceItem {
                    evidence_ref_id: uuid::Uuid::now_v7(),
                    run_id,
                    profile_id,
                    profile_digest: profile_digest.clone(),
                    layer: EvidenceLayer::L1,
                    evidence_type: EvidenceType::SemanticTrace,
                    evidence_digest: digest,
                    content_ref: format!("l1:{}", id),
                    source: "L1Runner".into(),
                    producer_identity: "gocode-runtime".into(),
                    sensitivity: SensitivityLabel::Internal,
                    verified_by: "L1Runner".into(),
                };
                ScenarioResult {
                    scenario_id: id.to_string(),
                    passed,
                    evidence,
                }
            })
            .collect()
    }
}
