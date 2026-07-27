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

impl<S, V, D, C> MigrationRouter<S, V, D, C>
where
    S: MigrationControlStore + MigrationRoutingStore,
    V: FenceValidationPort,
    D: MigrationDispatchPort,
    C: Clock + Send + Sync,
{
    /// Construct a router from its durable and protected-boundary authorities.
    pub fn new(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
    ) -> Self {
        Self::new_with_fallback_policy(
            store,
            features,
            fence,
            dispatch,
            clock,
            PreDispatchFallbackPolicy::Disabled,
        )
    }

    /// Construct a router with an explicit pre-dispatch fallback policy.
    pub fn new_with_fallback_policy(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
        fallback_policy: PreDispatchFallbackPolicy,
    ) -> Self {
        Self::new_with_routing_policies(
            store,
            features,
            fence,
            dispatch,
            clock,
            fallback_policy,
            LegacyAdmissionPolicy::Open,
        )
    }

    /// Construct a router with exact fallback and legacy-admission policies.
    pub fn new_with_routing_policies(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
        fallback_policy: PreDispatchFallbackPolicy,
        legacy_admission_policy: LegacyAdmissionPolicy,
    ) -> Self {
        Self {
            store,
            features,
            fence,
            dispatch,
            clock,
            fallback_policy,
            legacy_admission_policy,
            aggregate_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Route one new-work command exactly once for this process.
    ///
    /// Cross-process uncertainty remains fail-closed through the durable
    /// `Indeterminate` state and is never reclaimed automatically.
    pub async fn route_new_work(
        &self,
        request: RouteNewWorkRequest,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        validate_request(&request)?;
        let aggregate_lock = self.aggregate_lock(&request.aggregate_id)?;
        let guard = aggregate_lock.lock().await;
        let result = self.route_exclusive(request.clone()).await;
        drop(guard);
        self.release_aggregate_lock(&request.aggregate_id, &aggregate_lock)?;
        result
    }

    async fn route_exclusive(
        &self,
        request: RouteNewWorkRequest,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        let existing = self
            .store
            .load_runtime_binding(request.aggregate_id.clone(), &request.routing_unit)
            .map_err(MigrationRoutingError::Store)?;
        let (binding, intent) = if let Some(binding) = existing {
            let intent = self
                .store
                .load_dispatch_intent(request.aggregate_id.clone())
                .map_err(MigrationRoutingError::Store)?
                .ok_or(MigrationRoutingError::Store(
                    MigrationStoreError::IntegrityViolation,
                ))?;
            validate_existing_intent(&intent, &request)?;
            (binding, intent)
        } else {
            let snapshot = self
                .store
                .load_routing_head(&request.routing_unit)
                .map_err(MigrationRoutingError::Store)?
                .ok_or(MigrationRoutingError::RoutingHeadNotFound)?;
            let fallback_policy = self.select_pre_dispatch_policy(&snapshot.authority, &request)?;
            self.fence
                .validate_ingress(snapshot.routing_generation, snapshot.fencing_token)
                .map_err(MigrationRoutingError::Fence)?;
            let bound_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
            let admission = self
                .store
                .bind_and_create_dispatch_intent(BindRuntimeRequest {
                    aggregate_id: request.aggregate_id.clone(),
                    routing_unit: request.routing_unit.clone(),
                    expected_snapshot: snapshot,
                    fallback_policy,
                    command_id: request.command_id,
                    idempotency_key: request.idempotency_key.clone(),
                    request_digest: request.request_digest,
                    bound_at,
                })
                .map_err(MigrationRoutingError::Store)?;
            (admission.binding().clone(), admission.intent().clone())
        };

        match intent.status {
            DispatchIntentStatus::Accepted => {
                return Ok(RouteDecision {
                    binding,
                    dispatch_status: intent.status,
                });
            }
            DispatchIntentStatus::RejectedBeforeAcceptance => {
                return Err(MigrationRoutingError::RejectedBeforeAcceptance);
            }
            DispatchIntentStatus::Indeterminate => {
                return Err(MigrationRoutingError::ReconciliationRequired);
            }
            DispatchIntentStatus::Pending => {}
        }

        self.dispatch_pending(binding, intent).await
    }

    fn select_pre_dispatch_policy(
        &self,
        authority: &RuntimeAuthority,
        request: &RouteNewWorkRequest,
    ) -> Result<PreDispatchFallbackPolicy, MigrationRoutingError> {
        if self.legacy_admission_policy == LegacyAdmissionPolicy::Closed
            && (matches!(authority, RuntimeAuthority::Source(_))
                || request.authority_preference == RouteAuthorityPreference::LegacySource)
        {
            return Err(MigrationRoutingError::LegacyAdmissionClosed);
        }
        if !matches!(authority, RuntimeAuthority::Candidate(_)) {
            return Ok(PreDispatchFallbackPolicy::Disabled);
        }
        if request.authority_preference == RouteAuthorityPreference::LegacySource {
            self.fallback_policy
                .validate_routing_unit(&request.routing_unit)
                .map_err(|_| MigrationRoutingError::RoutingUnitMismatch)?;
            return match &self.fallback_policy {
                PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { .. } => {
                    Ok(self.fallback_policy.clone())
                }
                PreDispatchFallbackPolicy::Disabled => {
                    Err(MigrationRoutingError::RoutingUnitMismatch)
                }
            };
        }
        match validate_candidate_claim(authority, request, &self.features) {
            Ok(()) => Ok(PreDispatchFallbackPolicy::Disabled),
            Err(error @ MigrationRoutingError::Feature(_)) => {
                self.fallback_policy
                    .validate_routing_unit(&request.routing_unit)
                    .map_err(|_| MigrationRoutingError::RoutingUnitMismatch)?;
                match &self.fallback_policy {
                    PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { .. } => {
                        Ok(self.fallback_policy.clone())
                    }
                    PreDispatchFallbackPolicy::Disabled => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn dispatch_pending(
        &self,
        binding: RuntimeBinding,
        intent: RoutingDispatchIntent,
    ) -> Result<RouteDecision, MigrationRoutingError> {
        let claimed_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
        let claim = self
            .store
            .claim_dispatch(binding.aggregate_id.clone(), intent.command_id, claimed_at)
            .map_err(MigrationRoutingError::Store)?;
        let claimed = match claim {
            DispatchClaim::Claimed(claimed) => claimed,
            DispatchClaim::Existing(existing) => {
                return terminal_decision(binding, existing.status);
            }
        };
        if claimed.status != DispatchIntentStatus::Indeterminate {
            return Err(MigrationRoutingError::Store(
                MigrationStoreError::IntegrityViolation,
            ));
        }
        let admitted = self
            .fence
            .validate_ingress(binding.routing_generation, binding.fencing_token)
            .map_err(MigrationRoutingError::Fence)?;
        if self.fence.validate_worker_dispatch(&admitted).is_err() {
            let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
            let recorded = self
                .store
                .record_dispatch_result(
                    binding.aggregate_id.clone(),
                    intent.command_id,
                    DispatchResultStatus::RejectedBeforeAcceptance,
                    recorded_at,
                )
                .map_err(MigrationRoutingError::Store)?;
            if recorded.status != DispatchIntentStatus::RejectedBeforeAcceptance {
                return Err(MigrationRoutingError::Store(
                    MigrationStoreError::IntegrityViolation,
                ));
            }
            return Err(MigrationRoutingError::RejectedBeforeAcceptance);
        }

        match self
            .dispatch
            .dispatch(binding.clone(), intent.command_id)
            .await
        {
            DispatchAttempt::Indeterminate | DispatchAttempt::AcceptedThenFailed => {
                Err(MigrationRoutingError::ReconciliationRequired)
            }
            DispatchAttempt::RejectedBeforeAcceptance => {
                let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
                let recorded = self
                    .store
                    .record_dispatch_result(
                        binding.aggregate_id.clone(),
                        intent.command_id,
                        DispatchResultStatus::RejectedBeforeAcceptance,
                        recorded_at,
                    )
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                if recorded.status != DispatchIntentStatus::RejectedBeforeAcceptance {
                    return Err(MigrationRoutingError::ReconciliationRequired);
                }
                Err(MigrationRoutingError::RejectedBeforeAcceptance)
            }
            DispatchAttempt::Accepted => {
                self.fence
                    .validate_confirmation(&admitted)
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                let recorded_at = self.clock.now().map_err(MigrationRoutingError::Clock)?;
                let recorded = self
                    .store
                    .record_dispatch_result(
                        binding.aggregate_id.clone(),
                        intent.command_id,
                        DispatchResultStatus::Accepted,
                        recorded_at,
                    )
                    .map_err(|_| MigrationRoutingError::ReconciliationRequired)?;
                if recorded.status != DispatchIntentStatus::Accepted {
                    return Err(MigrationRoutingError::ReconciliationRequired);
                }
                Ok(RouteDecision {
                    binding,
                    dispatch_status: recorded.status,
                })
            }
        }
    }

    fn aggregate_lock(
        &self,
        aggregate_id: &AggregateId,
    ) -> Result<Arc<AsyncMutex<()>>, MigrationRoutingError> {
        let mut locks = self
            .aggregate_locks
            .lock()
            .map_err(|_| MigrationRoutingError::Store(MigrationStoreError::Unavailable))?;
        if let Some(lock) = locks.get(aggregate_id).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(aggregate_id.clone(), Arc::downgrade(&lock));
        Ok(lock)
    }

    fn release_aggregate_lock(
        &self,
        aggregate_id: &AggregateId,
        lock: &Arc<AsyncMutex<()>>,
    ) -> Result<(), MigrationRoutingError> {
        let mut locks = self
            .aggregate_locks
            .lock()
            .map_err(|_| MigrationRoutingError::Store(MigrationStoreError::Unavailable))?;
        if Arc::strong_count(lock) == 1
            && locks
                .get(aggregate_id)
                .and_then(Weak::upgrade)
                .is_some_and(|registered| Arc::ptr_eq(&registered, lock))
        {
            locks.remove(aggregate_id);
        }
        Ok(())
    }
}

fn validate_request(request: &RouteNewWorkRequest) -> Result<(), MigrationRoutingError> {
    if request.request_digest.as_bytes() == &[0; 32]
        || request.feature_request.feature_profile != request.routing_unit.feature_profile
        || request.feature_request.contract_digest != request.routing_unit.contract_digest
        || request.feature_request.schema_digest != request.routing_unit.schema_digest
        || request.feature_request.config_digest != request.routing_unit.config_digest
    {
        return Err(MigrationRoutingError::RoutingUnitMismatch);
    }
    Ok(())
}

fn validate_candidate_claim(
    authority: &RuntimeAuthority,
    request: &RouteNewWorkRequest,
    registry: &VerifiedFeatureRegistry,
) -> Result<(), MigrationRoutingError> {
    let RuntimeAuthority::Candidate(generation) = authority else {
        return Ok(());
    };
    if request.feature_request.runtime_release != generation.as_str() {
        return Err(MigrationRoutingError::RoutingUnitMismatch);
    }
    registry
        .require_verified(&request.feature_request)
        .map(|_| ())
        .map_err(MigrationRoutingError::Feature)
}

fn validate_existing_intent(
    intent: &RoutingDispatchIntent,
    request: &RouteNewWorkRequest,
) -> Result<(), MigrationRoutingError> {
    if intent.aggregate_id != request.aggregate_id
        || intent.command_id != request.command_id
        || intent.idempotency_key != request.idempotency_key
        || intent.request_digest != request.request_digest
    {
        return Err(MigrationRoutingError::Store(
            MigrationStoreError::DispatchIntentConflict,
        ));
    }
    Ok(())
}

fn terminal_decision(
    binding: RuntimeBinding,
    status: DispatchIntentStatus,
) -> Result<RouteDecision, MigrationRoutingError> {
    match status {
        DispatchIntentStatus::Accepted => Ok(RouteDecision {
            binding,
            dispatch_status: status,
        }),
        DispatchIntentStatus::RejectedBeforeAcceptance => {
            Err(MigrationRoutingError::RejectedBeforeAcceptance)
        }
        DispatchIntentStatus::Pending | DispatchIntentStatus::Indeterminate => {
            Err(MigrationRoutingError::ReconciliationRequired)
        }
    }
}
