struct StoredPlanRow {
    plan_id: String,
    cycle_id: String,
    cycle_kind: i64,
    parent_cycle_id: Option<String>,
    source_generation: String,
    candidate_generation: String,
    phase: i64,
    status: i64,
    routing_unit_digest: Vec<u8>,
    gate_policy: String,
    plan_version: i64,
    created_at: i64,
    plan_blob: Vec<u8>,
}

impl StoredPlanRow {
    fn matches(
        &self,
        plan: &MigrationPlan,
        expected_plan_id: &gocode_application::migration::types::MigrationPlanId,
    ) -> Result<bool, MigrationStoreError> {
        let (cycle_kind, parent_cycle_id) = cycle_parts(&plan.cycle_kind);
        Ok(self.plan_id == plan.plan_id.as_str()
            && &plan.plan_id == expected_plan_id
            && self.cycle_id == plan.cycle_id.as_str()
            && self.cycle_kind == cycle_kind
            && self.parent_cycle_id.as_deref() == parent_cycle_id
            && self.source_generation == plan.source.as_str()
            && self.candidate_generation == plan.candidate.as_str()
            && self.phase == i64::from(phase_tag(plan.phase))
            && self.status == i64::from(status_tag(plan.status))
            && self.routing_unit_digest == plan.routing_unit.digest().as_bytes()
            && self.gate_policy == plan.gate_policy.as_str()
            && self.plan_version == u64_to_i64(plan.plan_version)?
            && self.created_at == plan.created_at.as_unix_micros())
    }
}
