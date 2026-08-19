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
