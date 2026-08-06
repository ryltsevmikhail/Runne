use thiserror::Error;

pub struct ProviderOperationalTelemetryScope {
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    launch_generation: u64,
    fencing_token: u64,
    profile_digest: [u8; 32],
    observed_at_unix_seconds: u64,
}

impl ProviderOperationalTelemetryScope {
    pub fn new(
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        launch_generation: u64,
        fencing_token: u64,
        profile_digest: [u8; 32],
        observed_at_unix_seconds: u64,
    ) -> Result<Self, ProviderOperationalTelemetrySourceError> {
        if runtime_authority_id == [0; 16]
            || database_generation == 0
            || launch_generation == 0
            || fencing_token == 0
            || profile_digest == [0; 32]
        {
            return Err(ProviderOperationalTelemetrySourceError::Unavailable);
        }

        Ok(Self {
            runtime_authority_id,
            database_generation,
            launch_generation,
            fencing_token,
            profile_digest,
            observed_at_unix_seconds,
        })
    }

    pub const fn runtime_authority_id(&self) -> [u8; 16] {
        self.runtime_authority_id
    }

    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.observed_at_unix_seconds
    }
}

pub struct ProviderDurableOperationalTelemetry {
    accounting: Option<ProviderOperationalAccounting>,
    provider_effect_authorities: Option<ProviderOperationalExpiryAggregate>,
    provider_approval_lease: Option<ProviderOperationalExpiryAggregate>,
    committed_provider_effects: Option<ProviderOperationalExpiryAggregate>,
    uncertain_attempts: Option<u64>,
}

impl ProviderDurableOperationalTelemetry {
    pub const fn new(
        accounting: Option<ProviderOperationalAccounting>,
        provider_effect_authorities: Option<ProviderOperationalExpiryAggregate>,
        provider_approval_lease: Option<ProviderOperationalExpiryAggregate>,
        committed_provider_effects: Option<ProviderOperationalExpiryAggregate>,
        uncertain_attempts: Option<u64>,
    ) -> Self {
        Self {
            accounting,
            provider_effect_authorities,
            provider_approval_lease,
            committed_provider_effects,
            uncertain_attempts,
        }
    }

    pub const fn accounting(&self) -> Option<ProviderOperationalAccounting> {
        self.accounting
    }

    pub const fn provider_effect_authorities(&self) -> Option<ProviderOperationalExpiryAggregate> {
        self.provider_effect_authorities
    }

    pub const fn provider_approval_lease(&self) -> Option<ProviderOperationalExpiryAggregate> {
        self.provider_approval_lease
    }

    pub const fn committed_provider_effects(&self) -> Option<ProviderOperationalExpiryAggregate> {
        self.committed_provider_effects
    }

    pub const fn uncertain_attempts(&self) -> Option<u64> {
        self.uncertain_attempts
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderOperationalAccounting {
    token_limit: u64,
    token_reserved: u64,
    token_settled: u64,
    token_remaining: u64,
    cost_limit_micro_usd: u64,
    cost_reserved_micro_usd: u64,
    cost_settled_micro_usd: u64,
    cost_remaining_micro_usd: u64,
}

impl ProviderOperationalAccounting {
    pub fn new(
        token_limit: u64,
        token_reserved: u64,
        token_settled: u64,
        cost_limit_micro_usd: u64,
        cost_reserved_micro_usd: u64,
        cost_settled_micro_usd: u64,
    ) -> Result<Self, ProviderOperationalTelemetrySourceError> {
        let token_remaining = remaining(token_limit, token_reserved, token_settled)?;
        let cost_remaining_micro_usd = remaining(
            cost_limit_micro_usd,
            cost_reserved_micro_usd,
            cost_settled_micro_usd,
        )?;

        Ok(Self {
            token_limit,
            token_reserved,
            token_settled,
            token_remaining,
            cost_limit_micro_usd,
            cost_reserved_micro_usd,
            cost_settled_micro_usd,
            cost_remaining_micro_usd,
        })
    }

    pub const fn token_budget(&self) -> (u64, u64, u64, u64) {
        (
            self.token_limit,
            self.token_reserved,
            self.token_settled,
            self.token_remaining,
        )
    }

    pub const fn cost_budget_micro_usd(&self) -> (u64, u64, u64, u64) {
        (
            self.cost_limit_micro_usd,
            self.cost_reserved_micro_usd,
            self.cost_settled_micro_usd,
            self.cost_remaining_micro_usd,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderOperationalExpiryAggregate {
    active_count: u64,
    expired_active_count: u64,
    nearest_unexpired_expiry_unix_seconds: Option<u64>,
}

impl ProviderOperationalExpiryAggregate {
    pub fn new(
        active_count: u64,
        expired_active_count: u64,
        nearest_unexpired_expiry_unix_seconds: Option<u64>,
    ) -> Result<Self, ProviderOperationalTelemetrySourceError> {
        if expired_active_count > active_count {
            return Err(ProviderOperationalTelemetrySourceError::Unavailable);
        }

        Ok(Self {
            active_count,
            expired_active_count,
            nearest_unexpired_expiry_unix_seconds,
        })
    }

    pub const fn values(&self) -> (u64, u64, Option<u64>) {
        (
            self.active_count,
            self.expired_active_count,
            self.nearest_unexpired_expiry_unix_seconds,
        )
    }
}

pub trait ProviderOperationalTelemetrySource: Send + Sync {
    fn read_durable_operational_telemetry(
        &self,
        scope: ProviderOperationalTelemetryScope,
    ) -> Result<ProviderDurableOperationalTelemetry, ProviderOperationalTelemetrySourceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderOperationalTelemetrySourceError {
    #[error("provider operational telemetry is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderRecoveryObservationAvailability {
    Complete,
    Truncated,
    Unavailable,
}

pub struct ProviderRecoveryObservation {
    availability: ProviderRecoveryObservationAvailability,
    observed_count: Option<u64>,
    dropped_event_count: u64,
    drop_counter_saturated: bool,
}

impl ProviderRecoveryObservation {
    pub fn new(
        availability: ProviderRecoveryObservationAvailability,
        observed_count: Option<u64>,
        dropped_event_count: u64,
        drop_counter_saturated: bool,
    ) -> Result<Self, ProviderOperationalTelemetrySourceError> {
        let valid = match availability {
            ProviderRecoveryObservationAvailability::Complete => {
                observed_count.is_some() && dropped_event_count == 0 && !drop_counter_saturated
            }
            ProviderRecoveryObservationAvailability::Truncated => {
                observed_count.is_some() && (dropped_event_count > 0 || drop_counter_saturated)
            }
            ProviderRecoveryObservationAvailability::Unavailable => observed_count.is_none(),
        } && (drop_counter_saturated == (dropped_event_count == u64::MAX));

        if !valid {
            return Err(ProviderOperationalTelemetrySourceError::Unavailable);
        }

        Ok(Self {
            availability,
            observed_count,
            dropped_event_count,
            drop_counter_saturated,
        })
    }

    pub const fn availability(&self) -> ProviderRecoveryObservationAvailability {
        self.availability
    }

    pub const fn observed_count(&self) -> Option<u64> {
        self.observed_count
    }

    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
    }

    pub const fn drop_counter_saturated(&self) -> bool {
        self.drop_counter_saturated
    }
}

pub trait ProviderRecoveryObserver: Send + Sync {
    fn observe_recovered_terminal_output(&self) -> Result<(), ProviderRecoveryObserverError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderRecoveryObserverError {
    #[error("provider recovery observation is unavailable")]
    Unavailable,
}

fn remaining(
    limit: u64,
    reserved: u64,
    settled: u64,
) -> Result<u64, ProviderOperationalTelemetrySourceError> {
    limit
        .checked_sub(reserved)
        .and_then(|value| value.checked_sub(settled))
        .ok_or(ProviderOperationalTelemetrySourceError::Unavailable)
}
