use gocode_domain::timestamp::Timestamp;

use super::{
    error::MigrationError,
    types::{GatePolicyRef, MigrationCycleId, MigrationPlanId, RoutingUnit, RuntimeGenerationRef},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    Baseline,
    Foundation,
    ReadOnlyParity,
    SimulatedShadow,
    InternalCanary,
    CohortRollout,
    DefaultNative,
    DrainDeprecate,
    Retired,
}

impl MigrationPhase {
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Baseline => Some(Self::Foundation),
            Self::Foundation => Some(Self::ReadOnlyParity),
            Self::ReadOnlyParity => Some(Self::SimulatedShadow),
            Self::SimulatedShadow => Some(Self::InternalCanary),
            Self::InternalCanary => Some(Self::CohortRollout),
            Self::CohortRollout => Some(Self::DefaultNative),
            Self::DefaultNative => Some(Self::DrainDeprecate),
            Self::DrainDeprecate => Some(Self::Retired),
            Self::Retired => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCycleKind {
    Forward,
    Rollback { parent_cycle_id: MigrationCycleId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPlanStatus {
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub cycle_kind: MigrationCycleKind,
    pub source: RuntimeGenerationRef,
    pub candidate: RuntimeGenerationRef,
    pub phase: MigrationPhase,
    pub status: MigrationPlanStatus,
    pub routing_unit: RoutingUnit,
    pub gate_policy: GatePolicyRef,
    pub plan_version: u64,
    pub created_at: Timestamp,
}

impl MigrationPlan {
    pub fn advance(
        &mut self,
        target: MigrationPhase,
        expected_version: u64,
    ) -> Result<(), MigrationError> {
        if self.status != MigrationPlanStatus::Active || self.phase == MigrationPhase::Retired {
            return Err(MigrationError::TerminalPlanImmutable);
        }
        if expected_version != self.plan_version {
            return Err(MigrationError::PlanVersionConflict {
                expected: expected_version,
                actual: self.plan_version,
            });
        }
        if self.phase.next() != Some(target) {
            return Err(MigrationError::InvalidPhaseTransition {
                from: self.phase,
                to: target,
            });
        }

        let next_version = self
            .plan_version
            .checked_add(1)
            .ok_or(MigrationError::ArithmeticOverflow)?;
        self.phase = target;
        self.plan_version = next_version;
        Ok(())
    }

    pub fn new_rollback(
        cycle_id: MigrationCycleId,
        parent: &Self,
        routing_unit: RoutingUnit,
        gate_policy: GatePolicyRef,
        created_at: Timestamp,
    ) -> Result<Self, MigrationError> {
        if cycle_id == parent.cycle_id {
            return Err(MigrationError::RollbackIneligible);
        }

        Ok(Self {
            plan_id: parent.plan_id.clone(),
            cycle_id,
            cycle_kind: MigrationCycleKind::Rollback {
                parent_cycle_id: parent.cycle_id.clone(),
            },
            source: parent.candidate.clone(),
            candidate: parent.source.clone(),
            phase: MigrationPhase::Baseline,
            status: MigrationPlanStatus::Active,
            routing_unit,
            gate_policy,
            plan_version: 0,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use gocode_domain::timestamp::Timestamp;

    use super::*;
    use crate::migration::{
        error::MigrationError,
        types::{
            ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
            GatePolicyRef, MigrationCycleId, MigrationPlanId, RoutingUnit, RuntimeGenerationRef,
        },
    };

    #[test]
    fn phases_advance_only_to_the_adjacent_phase() {
        let mut plan = test_plan(MigrationPhase::Baseline);
        plan.advance(MigrationPhase::Foundation, 0).unwrap();
        assert_eq!(plan.phase, MigrationPhase::Foundation);
        assert_eq!(plan.plan_version, 1);

        let before = plan.clone();
        assert_eq!(
            plan.advance(MigrationPhase::SimulatedShadow, 1),
            Err(MigrationError::InvalidPhaseTransition {
                from: MigrationPhase::Foundation,
                to: MigrationPhase::SimulatedShadow,
            })
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn retired_plan_is_immutable() {
        let mut plan = test_plan(MigrationPhase::Retired);
        let before = plan.clone();
        assert_eq!(
            plan.advance(MigrationPhase::Retired, 0),
            Err(MigrationError::TerminalPlanImmutable)
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn rollback_cycle_requires_a_distinct_cycle_and_parent() {
        let parent = test_plan(MigrationPhase::InternalCanary);
        let rollback = MigrationPlan::new_rollback(
            MigrationCycleId::new("cycle-rb").unwrap(),
            &parent,
            test_routing_unit(),
            GatePolicyRef::new("policy-v1").unwrap(),
            Timestamp::from_unix_micros(10),
        )
        .unwrap();
        assert_eq!(rollback.phase, MigrationPhase::Baseline);
        assert!(matches!(
            rollback.cycle_kind,
            MigrationCycleKind::Rollback { ref parent_cycle_id }
                if parent_cycle_id == &parent.cycle_id
        ));
    }
    #[test]
    fn new_rollback_rejects_parent_cycle_id() {
        let parent = test_plan(MigrationPhase::SimulatedShadow);
        assert_eq!(
            MigrationPlan::new_rollback(
                parent.cycle_id.clone(),
                &parent,
                test_routing_unit(),
                GatePolicyRef::new("policy-v1").unwrap(),
                Timestamp::from_unix_micros(10),
            ),
            Err(MigrationError::RollbackIneligible)
        );
    }


    fn test_plan(phase: MigrationPhase) -> MigrationPlan {
        MigrationPlan {
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            cycle_kind: MigrationCycleKind::Forward,
            source: RuntimeGenerationRef::new("runtime-legacy").unwrap(),
            candidate: RuntimeGenerationRef::new("runtime-native").unwrap(),
            phase,
            status: MigrationPlanStatus::Active,
            routing_unit: test_routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(1),
        }
    }

    fn test_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            feature_profile: FeatureProfileRef::new(
                "default",
                1,
                ArtifactDigest::from_bytes([1; 32]),
            )
            .unwrap(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            schema_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
        }
    }
}
