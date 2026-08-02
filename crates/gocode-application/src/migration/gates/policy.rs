/// Immutable gate policy for one production phase boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseGatePolicy {
    target: MigrationPhase,
    revision: u16,
    required: &'static [GateFamily],
}

impl PhaseGatePolicy {
    /// Resolve the currently implemented policy for a production phase.
    pub const fn for_target(target: MigrationPhase) -> Option<Self> {
        match target {
            MigrationPhase::InternalCanary => Some(Self {
                target,
                revision: 1,
                required: PHASE_4,
            }),
            MigrationPhase::CohortRollout => Some(Self {
                target,
                revision: 2,
                required: PHASE_5,
            }),
            MigrationPhase::DefaultNative => Some(Self {
                target,
                revision: 3,
                required: PHASE_6,
            }),
            MigrationPhase::Baseline
            | MigrationPhase::Foundation
            | MigrationPhase::ReadOnlyParity
            | MigrationPhase::SimulatedShadow
            | MigrationPhase::DrainDeprecate
            | MigrationPhase::Retired => None,
        }
    }

    /// Production phase protected by this policy.
    pub const fn target(self) -> MigrationPhase {
        self.target
    }

    /// Stable revision of the phase policy.
    pub const fn revision(self) -> u16 {
        self.revision
    }

    /// Gate families required by this policy in canonical order.
    pub const fn required(self) -> &'static [GateFamily] {
        self.required
    }

    /// Select and validate the latest evidence for every required family.
    pub fn validate(
        self,
        history: &[MigrationEvidence],
        context: &GateContext,
    ) -> Result<ValidatedGateSet, GateSetValidationError> {
        let mut members = Vec::with_capacity(self.required.len());
        for family in self.required {
            let evidence = history.iter().rev().find_map(|evidence| {
                let MigrationEvidence::ProductionGate(gate) = evidence else {
                    return None;
                };
                (gate.family == *family).then_some(gate)
            });
            let evidence = evidence.ok_or(GateSetValidationError::Missing { family: *family })?;
            evidence.applies_to(context).map_err(|reason| {
                GateSetValidationError::Inapplicable {
                    family: *family,
                    reason,
                }
            })?;
            members.push(evidence.clone());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"gocode-migration-gate-set\x01");
        hasher.update([migration_phase_tag(self.target)]);
        hasher.update(self.revision.to_be_bytes());
        for evidence in &members {
            hasher.update([evidence.family as u8]);
            hasher.update(
                MigrationEvidence::ProductionGate(evidence.clone())
                    .semantic_digest()
                    .as_bytes(),
            );
        }
        Ok(ValidatedGateSet {
            target: self.target,
            policy_revision: self.revision,
            members,
            digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        })
    }
}
