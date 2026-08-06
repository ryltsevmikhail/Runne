use core::fmt;

use serde::{Deserialize, Serialize};

pub const OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1: u32 = 1;
pub const MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1: usize = 65_536;
pub const OPERATIONAL_TELEMETRY_CAPABILITY_V1: &str = "runtime.operational-telemetry.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalTelemetryContractErrorV1 {
    Unavailable,
}

impl fmt::Display for OperationalTelemetryContractErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operational telemetry unavailable")
    }
}

impl std::error::Error for OperationalTelemetryContractErrorV1 {}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryFreshnessV1 {
    #[serde(rename = "observed_in_current_cycle")]
    ObservedInCurrentCycle,
    #[serde(rename = "unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryCompletenessV1 {
    #[serde(rename = "complete")]
    Complete,
    #[serde(rename = "partial")]
    Partial,
    #[serde(rename = "unavailable")]
    Unavailable,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TelemetrySectionMetaV1 {
    observed_at_unix_seconds: u64,
    freshness: TelemetryFreshnessV1,
    completeness: TelemetryCompletenessV1,
}

impl TelemetrySectionMetaV1 {
    pub fn new(
        observed_at_unix_seconds: u64,
        freshness: TelemetryFreshnessV1,
        completeness: TelemetryCompletenessV1,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        match (freshness, completeness) {
            (TelemetryFreshnessV1::ObservedInCurrentCycle, TelemetryCompletenessV1::Complete)
            | (TelemetryFreshnessV1::ObservedInCurrentCycle, TelemetryCompletenessV1::Partial)
            | (TelemetryFreshnessV1::Unavailable, TelemetryCompletenessV1::Unavailable) => {
                Ok(Self {
                    observed_at_unix_seconds,
                    freshness,
                    completeness,
                })
            }
            _ => Err(OperationalTelemetryContractErrorV1::Unavailable),
        }
    }

    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
    pub const fn freshness(&self) -> TelemetryFreshnessV1 {
        self.freshness
    }
    pub const fn completeness(&self) -> TelemetryCompletenessV1 {
        self.completeness
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeBudgetV1 {
    limit: u64,
    reserved: u64,
    settled: u64,
    remaining: u64,
}

impl RuntimeBudgetV1 {
    pub fn new(
        limit: u64,
        reserved: u64,
        settled: u64,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        let used = reserved
            .checked_add(settled)
            .ok_or(OperationalTelemetryContractErrorV1::Unavailable)?;
        let remaining = limit
            .checked_sub(used)
            .ok_or(OperationalTelemetryContractErrorV1::Unavailable)?;
        Ok(Self {
            limit,
            reserved,
            settled,
            remaining,
        })
    }

    pub const fn limit(&self) -> u64 {
        self.limit
    }
    pub const fn reserved(&self) -> u64 {
        self.reserved
    }
    pub const fn settled(&self) -> u64 {
        self.settled
    }
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpiryAggregateV1 {
    active_count: u64,
    expired_active_count: u64,
    nearest_unexpired_expiry_unix_seconds: Option<u64>,
}

impl ExpiryAggregateV1 {
    pub fn new(
        active_count: u64,
        expired_active_count: u64,
        nearest_unexpired_expiry_unix_seconds: Option<u64>,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, OperationalTelemetryContractErrorV1> {
        let aggregate = Self {
            active_count,
            expired_active_count,
            nearest_unexpired_expiry_unix_seconds,
        };
        aggregate.validate_for(observed_at_unix_seconds)?;
        Ok(aggregate)
    }

    pub const fn active_count(&self) -> u64 {
        self.active_count
    }
    pub const fn expired_active_count(&self) -> u64 {
        self.expired_active_count
    }
    pub const fn nearest_unexpired_expiry_unix_seconds(&self) -> Option<u64> {
        self.nearest_unexpired_expiry_unix_seconds
    }

    pub(crate) fn validate_for(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<(), OperationalTelemetryContractErrorV1> {
        if self.expired_active_count > self.active_count
            || self
                .nearest_unexpired_expiry_unix_seconds
                .is_some_and(|expiry| expiry <= observed_at_unix_seconds)
        {
            return Err(OperationalTelemetryContractErrorV1::Unavailable);
        }
        Ok(())
    }
}
