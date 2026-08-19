//! Durable runtime binding and write-ahead dispatch contracts.

use runne_domain::{
    id::{AggregateId, CommandId, IdempotencyKey},
    timestamp::Timestamp,
};

use super::{
    ports::MigrationStoreError,
    rollout::PreDispatchFallbackPolicy,
    types::{ArtifactDigest, RoutingSnapshot, RoutingUnit, RuntimeBinding},
};

/// Durable dispatch state for one newly bound aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchIntentStatus {
    /// Binding and intent are durable; no external dispatch has started.
    Pending,
    /// Dispatch may have reached the selected runtime and requires reconciliation.
    Indeterminate,
    /// Selected runtime durably accepted the command.
    Accepted,
    /// Selected runtime proved rejection before acceptance.
    RejectedBeforeAcceptance,
}

/// Closed result that may resolve an indeterminate dispatch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResultStatus {
    /// Selected runtime accepted the command.
    Accepted,
    /// Selected runtime proved it rejected before acceptance.
    RejectedBeforeAcceptance,
}

/// Write-ahead identity and state for one routed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDispatchIntent {
    /// Aggregate pinned by the same atomic transaction.
    pub aggregate_id: AggregateId,
    /// Stable command identity.
    pub command_id: CommandId,
    /// Client retry identity.
    pub idempotency_key: IdempotencyKey,
    /// Canonical semantic input digest.
    pub request_digest: ArtifactDigest,
    /// Current durable dispatch state.
    pub status: DispatchIntentStatus,
    /// Persistence-authoritative creation time.
    pub created_at: Timestamp,
    /// Persistence-authoritative last transition time.
    pub updated_at: Timestamp,
}

/// Atomic binding and write-ahead intent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRuntimeRequest {
    /// New aggregate to pin.
    pub aggregate_id: AggregateId,
    /// Exact routing unit requested by the caller.
    pub routing_unit: RoutingUnit,
    /// Snapshot observed and fenced before the transaction.
    pub expected_snapshot: RoutingSnapshot,
    /// Explicit pre-dispatch authority-selection policy.
    pub fallback_policy: PreDispatchFallbackPolicy,
    /// Stable routed command identity.
    pub command_id: CommandId,
    /// Client retry identity.
    pub idempotency_key: IdempotencyKey,
    /// Canonical semantic input digest.
    pub request_digest: ArtifactDigest,
    /// Persistence timestamp supplied by the host clock authority.
    pub bound_at: Timestamp,
}

/// Result of atomically pinning an aggregate and creating its dispatch intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAdmission {
    /// This call created both durable records.
    Created {
        /// Immutable runtime binding.
        binding: RuntimeBinding,
        /// Pending write-ahead dispatch intent.
        intent: RoutingDispatchIntent,
    },
    /// Exact records already existed.
    Existing {
        /// Previously committed immutable runtime binding.
        binding: RuntimeBinding,
        /// Previously committed dispatch intent and current status.
        intent: RoutingDispatchIntent,
    },
}

/// Result of attempting to acquire the one-shot dispatch claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchClaim {
    /// This call durably moved `Pending` to `Indeterminate`.
    Claimed(RoutingDispatchIntent),
    /// A previous caller already moved the intent out of `Pending`.
    Existing(RoutingDispatchIntent),
}

impl DispatchClaim {
    /// Borrow the current durable intent.
    pub fn intent(&self) -> &RoutingDispatchIntent {
        match self {
            Self::Claimed(intent) | Self::Existing(intent) => intent,
        }
    }
}

impl RouteAdmission {
    /// Borrow the immutable binding.
    pub fn binding(&self) -> &RuntimeBinding {
        match self {
            Self::Created { binding, .. } | Self::Existing { binding, .. } => binding,
        }
    }

    /// Borrow the current dispatch intent.
    pub fn intent(&self) -> &RoutingDispatchIntent {
        match self {
            Self::Created { intent, .. } | Self::Existing { intent, .. } => intent,
        }
    }
}

/// Durable authority for runtime pinning and dispatch-state transitions.
pub trait MigrationRoutingStore: Send + Sync {
    /// Load an immutable binding and reject a routing-unit mismatch.
    fn load_runtime_binding(
        &self,
        aggregate_id: AggregateId,
        routing_unit: &RoutingUnit,
    ) -> Result<Option<RuntimeBinding>, MigrationStoreError>;

    /// Load the write-ahead dispatch intent for one aggregate.
    fn load_dispatch_intent(
        &self,
        aggregate_id: AggregateId,
    ) -> Result<Option<RoutingDispatchIntent>, MigrationStoreError>;

    /// Atomically create an immutable binding and its pending intent.
    fn bind_and_create_dispatch_intent(
        &self,
        request: BindRuntimeRequest,
    ) -> Result<RouteAdmission, MigrationStoreError>;

    /// Atomically move `Pending` to `Indeterminate` before external dispatch.
    ///
    /// Existing terminal or indeterminate state is returned unchanged and
    /// never reclaimed automatically.
    fn claim_dispatch(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        claimed_at: Timestamp,
    ) -> Result<DispatchClaim, MigrationStoreError>;

    /// Resolve an indeterminate attempt with a proved closed outcome.
    fn record_dispatch_result(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        status: DispatchResultStatus,
        recorded_at: Timestamp,
    ) -> Result<RoutingDispatchIntent, MigrationStoreError>;
}
