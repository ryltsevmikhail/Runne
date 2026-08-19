use std::sync::Arc;

use runne_api::{
    ExpiryAggregateV1, OperationalTelemetryQueryErrorV1, OperationalTelemetryQueryPort,
    RecoveryObservationStatusV1, RuntimeBudgetV1, RuntimeDurableAccountingV1,
    RuntimeDurableOperationalTelemetryV1, RuntimeOperationalTelemetrySnapshotV1,
    RuntimeRecoveryTransientV1, TelemetryCompletenessV1, TelemetryFreshnessV1,
    TelemetrySectionMetaV1,
};
use runne_application::ports::{Clock, ClockError};
use runne_application::provider::{
    ProviderDurableOperationalTelemetry, ProviderOperationalAccounting,
    ProviderOperationalExpiryAggregate, ProviderOperationalTelemetryScope,
    ProviderRecoveryObservation, ProviderRecoveryObservationAvailability,
};
use runne_domain::timestamp::Timestamp;
use runne_observability::operational::RecoveryObservationRegistry;
use runne_store::provider::SqliteProviderExecutionStore;

mod composition;
mod store;
mod unavailable;
pub(crate) use composition::compose_operational_telemetry_query;
use store::OperationalTelemetryStore;
pub(crate) use unavailable::unavailable_operational_telemetry_query;

pub(crate) struct DaemonOperationalTelemetryClock {
    now: Arc<dyn Fn() -> Result<Timestamp, ClockError> + Send + Sync>,
}

impl DaemonOperationalTelemetryClock {
    pub(crate) fn new(now: Arc<dyn Fn() -> Result<Timestamp, ClockError> + Send + Sync>) -> Self {
        Self { now }
    }
}

impl Clock for DaemonOperationalTelemetryClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        (self.now)()
    }
}

pub struct DaemonTelemetryLaunchContext {
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    launch_generation: u64,
    fencing_token: u64,
    profile_digest: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DaemonOperationalTelemetryCompositionError {
    Unavailable,
}

impl DaemonTelemetryLaunchContext {
    pub fn from_retained_fields(
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        runtime_generation: u64,
        fencing_token: u64,
        profile_digest: [u8; 32],
        authenticated_launch_generation: u64,
    ) -> Result<Self, DaemonOperationalTelemetryCompositionError> {
        if authenticated_launch_generation != runtime_generation {
            return Err(DaemonOperationalTelemetryCompositionError::Unavailable);
        }
        ProviderOperationalTelemetryScope::new(
            runtime_authority_id,
            database_generation,
            authenticated_launch_generation,
            fencing_token,
            profile_digest,
            0,
        )
        .map_err(|_| DaemonOperationalTelemetryCompositionError::Unavailable)?;
        Ok(Self {
            runtime_authority_id,
            database_generation,
            launch_generation: authenticated_launch_generation,
            fencing_token,
            profile_digest,
        })
    }

    pub fn scope(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<ProviderOperationalTelemetryScope, DaemonOperationalTelemetryCompositionError> {
        ProviderOperationalTelemetryScope::new(
            self.runtime_authority_id,
            self.database_generation,
            self.launch_generation,
            self.fencing_token,
            self.profile_digest,
            observed_at_unix_seconds,
        )
        .map_err(|_| DaemonOperationalTelemetryCompositionError::Unavailable)
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
}

pub struct DaemonOperationalTelemetryQueryService {
    store: OperationalTelemetryStore,
    registry: Arc<RecoveryObservationRegistry>,
    clock: Arc<dyn Clock + Send + Sync>,
    launch: DaemonTelemetryLaunchContext,
}

impl DaemonOperationalTelemetryQueryService {
    pub fn new(
        store: Arc<SqliteProviderExecutionStore>,
        registry: Arc<RecoveryObservationRegistry>,
        clock: Arc<dyn Clock + Send + Sync>,
        launch: DaemonTelemetryLaunchContext,
    ) -> Self {
        Self {
            store: OperationalTelemetryStore::Sqlite(store),
            registry,
            clock,
            launch,
        }
    }

    #[cfg(test)]
    fn new_for_test(
        source: Arc<dyn runne_application::provider::ProviderOperationalTelemetrySource>,
        registry: Arc<RecoveryObservationRegistry>,
        clock: Arc<dyn Clock + Send + Sync>,
        launch: DaemonTelemetryLaunchContext,
    ) -> Self {
        Self {
            store: OperationalTelemetryStore::Source(source),
            registry,
            clock,
            launch,
        }
    }
}

impl OperationalTelemetryQueryPort for DaemonOperationalTelemetryQueryService {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1> {
        let observed_at_unix_seconds = u64::try_from(
            self.clock
                .now()
                .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?
                .as_unix_micros(),
        )
        .ok()
        .and_then(|micros| micros.checked_div(1_000_000))
        .ok_or(OperationalTelemetryQueryErrorV1::Unavailable)?;
        let durable = self
            .store
            .read(
                self.launch
                    .scope(observed_at_unix_seconds)
                    .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?,
            )
            .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?;
        RuntimeOperationalTelemetrySnapshotV1::new(
            observed_at_unix_seconds,
            self.launch.launch_generation(),
            durable_dto(durable, observed_at_unix_seconds)?,
            recovery_dto(
                self.registry.snapshot_recovery_observation(),
                observed_at_unix_seconds,
            )?,
        )
        .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)
    }
}

fn durable_dto(
    durable: ProviderDurableOperationalTelemetry,
    observed_at_unix_seconds: u64,
) -> Result<RuntimeDurableOperationalTelemetryV1, OperationalTelemetryQueryErrorV1> {
    let accounting = durable.accounting().map(accounting_dto).transpose()?;
    let authorities = durable
        .provider_effect_authorities()
        .map(|value| aggregate_dto(value, observed_at_unix_seconds))
        .transpose()?;
    let approval = durable
        .provider_approval_lease()
        .map(|value| aggregate_dto(value, observed_at_unix_seconds))
        .transpose()?;
    let effects = durable
        .committed_provider_effects()
        .map(|value| aggregate_dto(value, observed_at_unix_seconds))
        .transpose()?;
    let uncertain = durable.uncertain_attempts();
    let present = [
        accounting.is_some(),
        authorities.is_some(),
        approval.is_some(),
        effects.is_some(),
        uncertain.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    let (freshness, completeness) = if present == 0 {
        (
            TelemetryFreshnessV1::Unavailable,
            TelemetryCompletenessV1::Unavailable,
        )
    } else if present == 5 {
        (
            TelemetryFreshnessV1::ObservedInCurrentCycle,
            TelemetryCompletenessV1::Complete,
        )
    } else {
        (
            TelemetryFreshnessV1::ObservedInCurrentCycle,
            TelemetryCompletenessV1::Partial,
        )
    };
    RuntimeDurableOperationalTelemetryV1::new(
        TelemetrySectionMetaV1::new(observed_at_unix_seconds, freshness, completeness)
            .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?,
        accounting,
        authorities,
        approval,
        effects,
        uncertain,
    )
    .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)
}

fn accounting_dto(
    accounting: ProviderOperationalAccounting,
) -> Result<RuntimeDurableAccountingV1, OperationalTelemetryQueryErrorV1> {
    let (token_limit, token_reserved, token_settled, token_remaining) = accounting.token_budget();
    let (cost_limit, cost_reserved, cost_settled, cost_remaining) =
        accounting.cost_budget_micro_usd();
    let tokens = RuntimeBudgetV1::new(token_limit, token_reserved, token_settled)
        .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?;
    let cost_micro_usd = RuntimeBudgetV1::new(cost_limit, cost_reserved, cost_settled)
        .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?;
    if tokens.remaining() != token_remaining || cost_micro_usd.remaining() != cost_remaining {
        return Err(OperationalTelemetryQueryErrorV1::Unavailable);
    }
    Ok(RuntimeDurableAccountingV1::new(tokens, cost_micro_usd))
}

fn aggregate_dto(
    aggregate: ProviderOperationalExpiryAggregate,
    observed_at_unix_seconds: u64,
) -> Result<ExpiryAggregateV1, OperationalTelemetryQueryErrorV1> {
    let (active, expired, nearest) = aggregate.values();
    ExpiryAggregateV1::new(active, expired, nearest, observed_at_unix_seconds)
        .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)
}

fn recovery_dto(
    recovery: ProviderRecoveryObservation,
    observed_at_unix_seconds: u64,
) -> Result<RuntimeRecoveryTransientV1, OperationalTelemetryQueryErrorV1> {
    let (freshness, completeness, status) = match recovery.availability() {
        ProviderRecoveryObservationAvailability::Complete => (
            TelemetryFreshnessV1::ObservedInCurrentCycle,
            TelemetryCompletenessV1::Complete,
            RecoveryObservationStatusV1::LowerBoundSinceLaunch,
        ),
        ProviderRecoveryObservationAvailability::Truncated => (
            TelemetryFreshnessV1::ObservedInCurrentCycle,
            TelemetryCompletenessV1::Partial,
            RecoveryObservationStatusV1::TruncatedLowerBoundSinceLaunch,
        ),
        ProviderRecoveryObservationAvailability::Unavailable => (
            TelemetryFreshnessV1::Unavailable,
            TelemetryCompletenessV1::Unavailable,
            RecoveryObservationStatusV1::Unavailable,
        ),
    };
    RuntimeRecoveryTransientV1::new(
        TelemetrySectionMetaV1::new(observed_at_unix_seconds, freshness, completeness)
            .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)?,
        status,
        recovery.observed_count(),
        recovery.dropped_event_count(),
        recovery.drop_counter_saturated(),
    )
    .map_err(|_| OperationalTelemetryQueryErrorV1::Unavailable)
}

#[cfg(test)]
mod tests;
