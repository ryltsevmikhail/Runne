use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use super::{
    ExpiryAggregateV1, OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1,
    OperationalTelemetryContractErrorV1, RecoveryObservationStatusV1, RuntimeBudgetV1,
    RuntimeDurableAccountingV1, RuntimeDurableOperationalTelemetryV1,
    RuntimeOperationalTelemetrySnapshotV1, RuntimeRecoveryTransientV1, TelemetryCompletenessV1,
    TelemetryFreshnessV1, TelemetrySectionMetaV1,
};

const INVALID_WIRE: &str = "invalid operational telemetry wire value";

fn invalid<E: serde::de::Error>(_: OperationalTelemetryContractErrorV1) -> E {
    E::custom(INVALID_WIRE)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SectionMetaWire {
    observed_at_unix_seconds: u64,
    freshness: TelemetryFreshnessV1,
    completeness: TelemetryCompletenessV1,
}

impl<'de> Deserialize<'de> for TelemetrySectionMetaV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SectionMetaWire::deserialize(deserializer)?;
        Self::new(
            wire.observed_at_unix_seconds,
            wire.freshness,
            wire.completeness,
        )
        .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetWire {
    limit: u64,
    reserved: u64,
    settled: u64,
    remaining: u64,
}

impl<'de> Deserialize<'de> for RuntimeBudgetV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BudgetWire::deserialize(deserializer)?;
        let budget = Self::new(wire.limit, wire.reserved, wire.settled).map_err(invalid)?;
        if budget.remaining() != wire.remaining {
            return Err(D::Error::custom(INVALID_WIRE));
        }
        Ok(budget)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpiryAggregateWire {
    active_count: u64,
    expired_active_count: u64,
    nearest_unexpired_expiry_unix_seconds: Option<u64>,
}

impl<'de> Deserialize<'de> for ExpiryAggregateV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ExpiryAggregateWire::deserialize(deserializer)?;
        Self::new(
            wire.active_count,
            wire.expired_active_count,
            wire.nearest_unexpired_expiry_unix_seconds,
            0,
        )
        .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountingWire {
    tokens: RuntimeBudgetV1,
    cost_micro_usd: RuntimeBudgetV1,
}

impl<'de> Deserialize<'de> for RuntimeDurableAccountingV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AccountingWire::deserialize(deserializer)?;
        Ok(Self::new(wire.tokens, wire.cost_micro_usd))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableWire {
    meta: TelemetrySectionMetaV1,
    accounting: Option<RuntimeDurableAccountingV1>,
    provider_effect_authorities: Option<ExpiryAggregateV1>,
    provider_approval_lease: Option<ExpiryAggregateV1>,
    committed_provider_effects: Option<ExpiryAggregateV1>,
    uncertain_attempts: Option<u64>,
}

impl<'de> Deserialize<'de> for RuntimeDurableOperationalTelemetryV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = DurableWire::deserialize(deserializer)?;
        Self::new(
            wire.meta,
            wire.accounting,
            wire.provider_effect_authorities,
            wire.provider_approval_lease,
            wire.committed_provider_effects,
            wire.uncertain_attempts,
        )
        .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryTransientWire {
    meta: TelemetrySectionMetaV1,
    status: RecoveryObservationStatusV1,
    observed_outbox_recoveries_in_generation: Option<u64>,
    dropped_event_count: u64,
    counter_saturated: bool,
}

impl<'de> Deserialize<'de> for RuntimeRecoveryTransientV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RecoveryTransientWire::deserialize(deserializer)?;
        Self::new(
            wire.meta,
            wire.status,
            wire.observed_outbox_recoveries_in_generation,
            wire.dropped_event_count,
            wire.counter_saturated,
        )
        .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotWire {
    schema_version: u32,
    observed_at_unix_seconds: u64,
    launch_generation: u64,
    durable: RuntimeDurableOperationalTelemetryV1,
    recovery_transient: RuntimeRecoveryTransientV1,
}

impl<'de> Deserialize<'de> for RuntimeOperationalTelemetrySnapshotV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SnapshotWire::deserialize(deserializer)?;
        if wire.schema_version != OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1 {
            return Err(D::Error::custom(INVALID_WIRE));
        }
        Self::new(
            wire.observed_at_unix_seconds,
            wire.launch_generation,
            wire.durable,
            wire.recovery_transient,
        )
        .map_err(invalid)
    }
}
