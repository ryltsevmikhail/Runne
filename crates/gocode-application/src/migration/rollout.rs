//! Phase-specific production rollout policies.

use std::time::Duration;

use gocode_domain::timestamp::Timestamp;

use super::{
    error::MigrationError,
    ports::CutoverIntent,
    types::{CohortSelector, GatePolicyRef, RoutingGeneration, RoutingUnit},
};

/// Maximum number of concurrently admitted commands in the internal canary.
pub const MAX_CANARY_ADMISSION_LIMIT: u32 = 1_024;
/// Maximum command admission bound for one cohort rollout step.
pub const MAX_ROLLOUT_ADMISSION_LIMIT: u32 = 1_000_000;

/// Exact bounded policy for Stage 4 Internal Canary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryPolicy {
    /// Exact cohort authorized by the cutover manifest.
    pub target_cohort: CohortSelector,
    /// Non-zero command admission bound.
    pub admission_limit: u32,
}

impl CanaryPolicy {
    /// Construct a bounded Internal Canary policy.
    pub fn new(
        target_cohort: CohortSelector,
        admission_limit: u32,
    ) -> Result<Self, MigrationError> {
        if admission_limit == 0 || admission_limit > MAX_CANARY_ADMISSION_LIMIT {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        Ok(Self {
            target_cohort,
            admission_limit,
        })
    }

    /// Require an exact routing-unit cohort match.
    pub fn validate_routing_unit(&self, unit: &RoutingUnit) -> Result<(), MigrationError> {
        if self.target_cohort != unit.cohort {
            return Err(MigrationError::RoutingUnitMismatch);
        }
        Ok(())
    }
}

/// Immutable bounded policy for one Stage 5 cohort expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutStep {
    /// Routing generation that this step is authorized to replace.
    pub previous_routing_generation: RoutingGeneration,
    /// Exact cohort expanded by this step.
    pub target_cohort: CohortSelector,
    /// Non-zero command admission bound after the step.
    pub admission_limit: u32,
    /// Minimum complete observation interval required before expansion.
    pub observation_window: Duration,
    /// Inclusive beginning of the observed interval.
    pub observed_from: Timestamp,
    /// Inclusive end of the observed interval.
    pub observed_until: Timestamp,
    /// Exact gate policy authority for the rollout step.
    pub required_gate_policy: GatePolicyRef,
}

impl RolloutStep {
    /// Construct a rollout step only after its observation interval is complete.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        previous_routing_generation: RoutingGeneration,
        target_cohort: CohortSelector,
        admission_limit: u32,
        observation_window: Duration,
        observed_from: Timestamp,
        observed_until: Timestamp,
        required_gate_policy: GatePolicyRef,
    ) -> Result<Self, MigrationError> {
        if admission_limit == 0 || admission_limit > MAX_ROLLOUT_ADMISSION_LIMIT {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if observation_window.is_zero()
            || !observation_interval_is_complete(observation_window, observed_from, observed_until)
        {
            return Err(MigrationError::ObservationWindowIncomplete);
        }
        Ok(Self {
            previous_routing_generation,
            target_cohort,
            admission_limit,
            observation_window,
            observed_from,
            observed_until,
            required_gate_policy,
        })
    }

    /// Validate the exact routing, generation, policy and evaluation boundary.
    pub fn validate_for_prepare(
        &self,
        unit: &RoutingUnit,
        current_generation: RoutingGeneration,
        gate_policy: &GatePolicyRef,
        evaluated_at: Timestamp,
    ) -> Result<(), MigrationError> {
        if self.target_cohort != unit.cohort {
            return Err(MigrationError::RoutingUnitMismatch);
        }
        if self.previous_routing_generation != current_generation {
            return Err(MigrationError::RoutingGenerationConflict {
                expected: self.previous_routing_generation,
                actual: current_generation,
            });
        }
        if &self.required_gate_policy != gate_policy {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if evaluated_at < self.observed_until {
            return Err(MigrationError::ObservationWindowIncomplete);
        }
        if !observation_interval_is_complete(
            self.observation_window,
            self.observed_from,
            self.observed_until,
        ) {
            return Err(MigrationError::ObservationWindowIncomplete);
        }
        Ok(())
    }
}

/// Phase-specific policy embedded in an immutable cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutoverPolicy {
    /// Stage 4 exact internal canary.
    InternalCanary(CanaryPolicy),
    /// Stage 5 bounded cohort expansion.
    CohortExpansion(RolloutStep),
}

impl CutoverPolicy {
    /// Non-zero admission bound authorized by this policy.
    pub const fn admission_limit(&self) -> u32 {
        match self {
            Self::InternalCanary(policy) => policy.admission_limit,
            Self::CohortExpansion(step) => step.admission_limit,
        }
    }

    /// Validate static identity and intent invariants.
    pub fn validate_identity(
        &self,
        intent: CutoverIntent,
        unit: &RoutingUnit,
    ) -> Result<(), MigrationError> {
        match (intent, self) {
            (CutoverIntent::InternalCanary, Self::InternalCanary(policy)) => {
                policy.validate_routing_unit(unit)
            }
            (CutoverIntent::CohortExpansion, Self::CohortExpansion(step)) => {
                if step.target_cohort != unit.cohort {
                    return Err(MigrationError::RoutingUnitMismatch);
                }
                if step.admission_limit == 0 || step.admission_limit > MAX_ROLLOUT_ADMISSION_LIMIT {
                    return Err(MigrationError::ProductionGatesUnavailable);
                }
                if step.observation_window.is_zero()
                    || !observation_interval_is_complete(
                        step.observation_window,
                        step.observed_from,
                        step.observed_until,
                    )
                {
                    return Err(MigrationError::ObservationWindowIncomplete);
                }
                Ok(())
            }
            _ => Err(MigrationError::ProductionGatesUnavailable),
        }
    }

    /// Validate invariants frozen with the manifest routing boundary.
    pub fn validate_manifest(
        &self,
        intent: CutoverIntent,
        unit: &RoutingUnit,
        expected_generation: RoutingGeneration,
        prepared_at: Timestamp,
    ) -> Result<(), MigrationError> {
        self.validate_identity(intent, unit)?;
        if let Self::CohortExpansion(step) = self {
            if step.previous_routing_generation != expected_generation {
                return Err(MigrationError::RoutingGenerationConflict {
                    expected: step.previous_routing_generation,
                    actual: expected_generation,
                });
            }
            if step.observed_until > prepared_at {
                return Err(MigrationError::ObservationWindowIncomplete);
            }
        }
        Ok(())
    }

    /// Validate prepare-time routing generation, gate policy and observation time.
    pub fn validate_for_prepare(
        &self,
        intent: CutoverIntent,
        unit: &RoutingUnit,
        current_generation: RoutingGeneration,
        gate_policy: &GatePolicyRef,
        evaluated_at: Timestamp,
    ) -> Result<(), MigrationError> {
        self.validate_manifest(intent, unit, current_generation, evaluated_at)?;
        match self {
            Self::InternalCanary(_) => Ok(()),
            Self::CohortExpansion(step) => {
                step.validate_for_prepare(unit, current_generation, gate_policy, evaluated_at)
            }
        }
    }
}

fn observation_interval_is_complete(
    required: Duration,
    observed_from: Timestamp,
    observed_until: Timestamp,
) -> bool {
    let Some(elapsed_micros) = observed_until
        .as_unix_micros()
        .checked_sub(observed_from.as_unix_micros())
    else {
        return false;
    };
    let Ok(elapsed_micros) = u128::try_from(elapsed_micros) else {
        return false;
    };
    elapsed_micros >= required.as_micros()
}
