/// Phase-specific policy embedded in an immutable cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutoverPolicy {
    /// Stage 4 exact internal canary.
    InternalCanary(CanaryPolicy),
    /// Stage 5 bounded cohort expansion.
    CohortExpansion(RolloutStep),
    /// Stage 6 candidate-default routing with an explicit pre-dispatch fallback boundary.
    DefaultNative(PreDispatchFallbackPolicy),
}

impl CutoverPolicy {
    /// Non-zero admission bound authorized by bounded rollout policies.
    pub const fn admission_limit(&self) -> Option<u32> {
        match self {
            Self::InternalCanary(policy) => Some(policy.admission_limit),
            Self::CohortExpansion(step) => Some(step.admission_limit),
            Self::DefaultNative(_) => None,
        }
    }

    /// Validate static identity and intent invariants.
    pub fn validate_identity(
        &self,
        intent: CutoverIntent,
        unit: &RoutingUnit,
    ) -> Result<(), MigrationError> {
        match (intent, self) {
            (
                CutoverIntent::InternalCanary | CutoverIntent::Rollback,
                Self::InternalCanary(policy),
            ) => policy.validate_routing_unit(unit),
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
            (CutoverIntent::DefaultNative, Self::DefaultNative(policy)) => {
                policy.validate_routing_unit(unit)
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
            Self::DefaultNative(_) => Ok(()),
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
