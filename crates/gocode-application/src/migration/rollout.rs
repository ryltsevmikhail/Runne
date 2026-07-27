//! Phase-specific production rollout policies.

use super::{
    error::MigrationError,
    types::{CohortSelector, RoutingUnit},
};

/// Maximum number of concurrently admitted commands in the internal canary.
pub const MAX_CANARY_ADMISSION_LIMIT: u32 = 1_024;

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
