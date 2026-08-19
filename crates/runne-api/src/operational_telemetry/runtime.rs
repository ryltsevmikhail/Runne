use serde::Serialize;

use super::{
    ExpiryAggregateV1, OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1,
    OperationalTelemetryContractErrorV1, RuntimeBudgetV1, TelemetryCompletenessV1,
    TelemetryFreshnessV1, TelemetrySectionMetaV1,
};

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDurableAccountingV1 {
    tokens: RuntimeBudgetV1,
    cost_micro_usd: RuntimeBudgetV1,
}

impl RuntimeDurableAccountingV1 {
    pub const fn new(tokens: RuntimeBudgetV1, cost_micro_usd: RuntimeBudgetV1) -> Self {
        Self {
            tokens,
            cost_micro_usd,
        }
    }
    pub const fn tokens(&self) -> &RuntimeBudgetV1 {
        &self.tokens
    }
    pub const fn cost_micro_usd(&self) -> &RuntimeBudgetV1 {
        &self.cost_micro_usd
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDurableOperationalTelemetryV1 {
    meta: TelemetrySectionMetaV1,
    accounting: Option<RuntimeDurableAccountingV1>,
    provider_effect_authorities: Option<ExpiryAggregateV1>,
    provider_approval_lease: Option<ExpiryAggregateV1>,
    committed_provider_effects: Option<ExpiryAggregateV1>,
    uncertain_attempts: Option<u64>,
}

impl RuntimeDurableOperationalTelemetryV1 {
    pub fn new(
        meta: TelemetrySectionMetaV1,
        accounting: Option<RuntimeDurableAccountingV1>,
        provider_effect_authorities: Option<ExpiryAggregateV1>,
        provider_approval_lease: Option<ExpiryAggregateV1>,
        committed_provider_effects: Option<ExpiryAggregateV1>,
        uncertain_attempts: Option<u64>,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        let present = [
            accounting.is_some(),
            provider_effect_authorities.is_some(),
            provider_approval_lease.is_some(),
            committed_provider_effects.is_some(),
            uncertain_attempts.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        let expected = match present {
            0 => TelemetryCompletenessV1::Unavailable,
            5 => TelemetryCompletenessV1::Complete,
            _ => TelemetryCompletenessV1::Partial,
        };
        if meta.completeness() != expected {
            return Err(OperationalTelemetryContractErrorV1::Unavailable);
        }
        for aggregate in [
            provider_effect_authorities.as_ref(),
            provider_approval_lease.as_ref(),
            committed_provider_effects.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            aggregate.validate_for(meta.observed_at_unix_seconds())?;
        }
        Ok(Self {
            meta,
            accounting,
            provider_effect_authorities,
            provider_approval_lease,
            committed_provider_effects,
            uncertain_attempts,
        })
    }

    pub const fn meta(&self) -> &TelemetrySectionMetaV1 {
        &self.meta
    }
    pub const fn accounting(&self) -> Option<&RuntimeDurableAccountingV1> {
        self.accounting.as_ref()
    }
    pub const fn provider_effect_authorities(&self) -> Option<&ExpiryAggregateV1> {
        self.provider_effect_authorities.as_ref()
    }
    pub const fn provider_approval_lease(&self) -> Option<&ExpiryAggregateV1> {
        self.provider_approval_lease.as_ref()
    }
    pub const fn committed_provider_effects(&self) -> Option<&ExpiryAggregateV1> {
        self.committed_provider_effects.as_ref()
    }
    pub const fn uncertain_attempts(&self) -> Option<u64> {
        self.uncertain_attempts
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum RecoveryObservationStatusV1 {
    #[serde(rename = "lower_bound_since_launch")]
    LowerBoundSinceLaunch,
    #[serde(rename = "truncated_lower_bound_since_launch")]
    TruncatedLowerBoundSinceLaunch,
    #[serde(rename = "unavailable")]
    Unavailable,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRecoveryTransientV1 {
    meta: TelemetrySectionMetaV1,
    status: RecoveryObservationStatusV1,
    observed_outbox_recoveries_in_generation: Option<u64>,
    dropped_event_count: u64,
    counter_saturated: bool,
}

impl RuntimeRecoveryTransientV1 {
    pub fn new(
        meta: TelemetrySectionMetaV1,
        status: RecoveryObservationStatusV1,
        observed_outbox_recoveries_in_generation: Option<u64>,
        dropped_event_count: u64,
        counter_saturated: bool,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        let valid = match status {
            RecoveryObservationStatusV1::LowerBoundSinceLaunch => {
                observed_outbox_recoveries_in_generation.is_some()
                    && dropped_event_count == 0
                    && !counter_saturated
                    && meta.freshness() == TelemetryFreshnessV1::ObservedInCurrentCycle
                    && meta.completeness() == TelemetryCompletenessV1::Complete
            }
            RecoveryObservationStatusV1::TruncatedLowerBoundSinceLaunch => {
                observed_outbox_recoveries_in_generation.is_some()
                    && (dropped_event_count > 0 || counter_saturated)
                    && meta.freshness() == TelemetryFreshnessV1::ObservedInCurrentCycle
                    && meta.completeness() == TelemetryCompletenessV1::Partial
            }
            RecoveryObservationStatusV1::Unavailable => {
                observed_outbox_recoveries_in_generation.is_none()
                    && meta.freshness() == TelemetryFreshnessV1::Unavailable
                    && meta.completeness() == TelemetryCompletenessV1::Unavailable
            }
        };
        if !valid || counter_saturated != (dropped_event_count == u64::MAX) {
            return Err(OperationalTelemetryContractErrorV1::Unavailable);
        }
        Ok(Self {
            meta,
            status,
            observed_outbox_recoveries_in_generation,
            dropped_event_count,
            counter_saturated,
        })
    }

    pub const fn meta(&self) -> &TelemetrySectionMetaV1 {
        &self.meta
    }
    pub const fn status(&self) -> RecoveryObservationStatusV1 {
        self.status
    }
    pub const fn observed_outbox_recoveries_in_generation(&self) -> Option<u64> {
        self.observed_outbox_recoveries_in_generation
    }
    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
    }
    pub const fn counter_saturated(&self) -> bool {
        self.counter_saturated
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOperationalTelemetrySnapshotV1 {
    schema_version: u32,
    observed_at_unix_seconds: u64,
    launch_generation: u64,
    durable: RuntimeDurableOperationalTelemetryV1,
    recovery_transient: RuntimeRecoveryTransientV1,
}

impl RuntimeOperationalTelemetrySnapshotV1 {
    pub fn new(
        observed_at_unix_seconds: u64,
        launch_generation: u64,
        durable: RuntimeDurableOperationalTelemetryV1,
        recovery_transient: RuntimeRecoveryTransientV1,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        if launch_generation == 0 {
            return Err(OperationalTelemetryContractErrorV1::Unavailable);
        }
        Ok(Self {
            schema_version: OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1,
            observed_at_unix_seconds,
            launch_generation,
            durable,
            recovery_transient,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    pub const fn durable(&self) -> &RuntimeDurableOperationalTelemetryV1 {
        &self.durable
    }
    pub const fn recovery_transient(&self) -> &RuntimeRecoveryTransientV1 {
        &self.recovery_transient
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalTelemetryQueryErrorV1 {
    Unavailable,
}

impl core::fmt::Display for OperationalTelemetryQueryErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operational telemetry unavailable")
    }
}

impl std::error::Error for OperationalTelemetryQueryErrorV1 {}

pub trait OperationalTelemetryQueryPort: Send + Sync {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1>;
}
