/// Immutable rollback-cycle artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackManifest {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub parent_plan_id: MigrationPlanId,
    pub routing_unit: RoutingUnit,
    pub candidate_high_water: u64,
    pub changed_state_inventory: ArtifactRef,
    pub reconciliation_report: ArtifactRef,
    pub reverse_migration_contract: Option<ArtifactRef>,
    pub expected_routing_generation: RoutingGeneration,
    pub operator_authorization: ArtifactRef,
    pub created_at: Timestamp,
}

impl RollbackManifest {
    /// Verify isolated-cycle identity and all immutable references.
    pub fn has_valid_identity(&self) -> bool {
        let mut artifacts = vec![
            &self.manifest,
            &self.changed_state_inventory,
            &self.reconciliation_report,
            &self.operator_authorization,
        ];
        if let Some(contract) = &self.reverse_migration_contract {
            artifacts.push(contract);
        }
        self.plan_id != self.parent_plan_id && all_artifacts_unique(artifacts)
    }
}

/// Immutable source-retirement artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementManifest {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub final_drain_report: ArtifactRef,
    /// Exact digest of the retirement-clear legacy reference inventory.
    pub reference_inventory_digest: ArtifactDigest,
    /// Evidence covering every claimed replacement platform tuple.
    pub platform_verification_set: ArtifactRef,
    /// Evidence that migration and rollback windows are closed.
    pub closed_windows_evidence: ArtifactRef,
    /// Evidence that legacy credentials, processes, and packages are disabled.
    pub disabled_legacy_authority: ArtifactRef,
    pub final_audit: ArtifactRef,
    pub removal_diff: ArtifactRef,
    /// Security and compatibility removal-suite result.
    pub removal_suite: ArtifactRef,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub created_at: Timestamp,
}

impl RetirementManifest {
    /// Verify final-retirement identity, retention, and artifact uniqueness.
    pub fn has_valid_identity(&self) -> bool {
        self.retention_until >= self.created_at
            && all_artifacts_unique([
                &self.manifest,
                &self.final_drain_report,
                &self.platform_verification_set,
                &self.closed_windows_evidence,
                &self.disabled_legacy_authority,
                &self.final_audit,
                &self.removal_diff,
                &self.removal_suite,
                &self.operator_authorization,
            ])
            && self.reference_inventory_digest.as_bytes() != &[0; 32]
    }
}
