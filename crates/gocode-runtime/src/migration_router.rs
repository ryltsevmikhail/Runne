//! Exclusive new-work routing with immutable bindings and durable dispatch intent.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, Weak},
};

use gocode_application::{
    migration::{
        error::MigrationError,
        feature_matrix::{FeatureClaimRequest, VerifiedFeatureRegistry},
        fence::{FenceError, FenceValidationPort},
        ports::{MigrationControlStore, MigrationStoreError},
        rollout::PreDispatchFallbackPolicy,
        routing::{
            BindRuntimeRequest, DispatchClaim, DispatchIntentStatus, DispatchResultStatus,
            MigrationRoutingStore, RoutingDispatchIntent,
        },
        types::{ArtifactDigest, RoutingUnit, RuntimeAuthority, RuntimeBinding},
    },
    ports::{Clock, ClockError},
};
use gocode_domain::id::{AggregateId, CommandId, IdempotencyKey};
use tokio::sync::Mutex as AsyncMutex;

use crate::migration_fence::MigrationFenceGuard;

/// External dispatch disposition observed at the protected runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchAttempt {
    /// The selected runtime proved acceptance.
    Accepted,
    /// The selected runtime accepted, then failed before a terminal reply.
    AcceptedThenFailed,
    /// The selected runtime proved rejection before acceptance.
    RejectedBeforeAcceptance,
    /// Acceptance cannot be proved either way and requires reconciliation.
    Indeterminate,
}

/// Caller intent for selecting current or explicitly retained legacy authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAuthorityPreference {
    /// Follow the current routing head and verified feature claim.
    Current,
    /// Request the explicitly published Source fallback route.
    LegacySource,
}

/// Stage-specific admission policy for creating new Source bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyAdmissionPolicy {
    /// Explicit legacy fallback may create new bindings when otherwise authorized.
    Open,
    /// No new legacy binding may be created.
    Closed,
}

/// Protected runtime dispatch boundary.
///
/// Implementations must validate the binding generation and fencing token in
/// the same critical section as external dispatch.
pub trait MigrationDispatchPort: Send + Sync {
    /// Dispatch one command to the immutable runtime authority.
    fn dispatch(
        &self,
        binding: RuntimeBinding,
        command_id: CommandId,
    ) -> impl Future<Output = DispatchAttempt> + Send;
}

/// Canonical request for assigning new work to a migration authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteNewWorkRequest {
    /// Aggregate that must remain pinned after its first admission.
    pub aggregate_id: AggregateId,
    /// Exact deployment, cohort and artifact scope.
    pub routing_unit: RoutingUnit,
    /// Exact release claim required for candidate authority.
    pub feature_request: FeatureClaimRequest,
    /// Stable command identity used by the durable dispatch intent.
    pub command_id: CommandId,
    /// Client retry identity.
    pub idempotency_key: IdempotencyKey,
    /// Canonical semantic request digest.
    pub request_digest: ArtifactDigest,
    /// Explicit current-or-legacy authority preference.
    pub authority_preference: RouteAuthorityPreference,
}

/// Durable routing result returned after proved acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    /// Immutable authority binding.
    pub binding: RuntimeBinding,
    /// Terminal durable dispatch state.
    pub dispatch_status: DispatchIntentStatus,
}

/// Closed routing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationRoutingError {
    /// Durable routing state is unavailable or inconsistent.
    Store(MigrationStoreError),
    /// Candidate feature evidence is absent or does not match exactly.
    Feature(MigrationError),
    /// Routing generation or token failed validation.
    Fence(FenceError),
    /// Host clock could not provide a persistence timestamp.
    Clock(ClockError),
    /// No routing head exists for the exact unit.
    RoutingHeadNotFound,
    /// Request fields disagree with the exact routing unit.
    RoutingUnitMismatch,
    /// Stage 7 closed admission for every new Source binding.
    LegacyAdmissionClosed,
    /// Dispatch may have reached the selected authority.
    ReconciliationRequired,
    /// The selected authority proved rejection before acceptance.
    RejectedBeforeAcceptance,
}

/// Exclusive router for new migration-scoped work.
pub struct MigrationRouter<S, V, D, C> {
    store: Arc<S>,
    features: Arc<VerifiedFeatureRegistry>,
    fence: MigrationFenceGuard<V>,
    dispatch: Arc<D>,
    clock: Arc<C>,
    fallback_policy: PreDispatchFallbackPolicy,
    legacy_admission_policy: LegacyAdmissionPolicy,
    aggregate_locks: Mutex<HashMap<AggregateId, Weak<AsyncMutex<()>>>>,
}

include!("migration_router/constructors.rs");
include!("migration_router/routing.rs");
include!("migration_router/dispatch.rs");
include!("migration_router/locks.rs");
include!("migration_router/helpers.rs");
