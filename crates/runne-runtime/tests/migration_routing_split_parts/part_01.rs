use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use runne_application::{
    migration::{
        feature_matrix::{
            FeatureClaimRequest, FeatureStatus, ReleaseFeatureClaim, VerifiedFeatureRegistry,
        },
        platform::{
            FilesystemClass, PlatformArchitecture, PlatformOs, PlatformTuple, PlatformVfs,
            ProcessModel,
        },
        rollout::PreDispatchFallbackPolicy,
        routing::{BindRuntimeRequest, MigrationRoutingStore},
        types::{
            ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
            FencingToken, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
            RuntimeAuthority, RuntimeBinding, RuntimeGenerationRef,
        },
    },
    ports::{Clock, ClockError},
};
use runne_domain::{
    id::{AggregateId, CommandId, IdempotencyKey, TaskRunId},
    timestamp::Timestamp,
};
use runne_platform::fence::FenceRegistry;
use runne_runtime::{
    migration_fence::MigrationFenceGuard,
    migration_router::{
        DispatchAttempt, LegacyAdmissionPolicy, MigrationDispatchPort, MigrationRouter,
        MigrationRoutingError, RouteAuthorityPreference, RouteNewWorkRequest,
    },
};
use runne_store::{
    migration_codec::encode_routing_snapshot, migration_store::SqliteMigrationControlStore,
};
use rusqlite::{Connection, params};

#[tokio::test]
async fn concurrent_duplicate_admission_creates_one_binding_and_one_dispatch() {
    let harness = RoutingHarness::new(candidate_snapshot(), matching_registry());
    let request = route_request();

    let (left, right) = tokio::join!(
        harness.router.route_new_work(request.clone()),
        harness.router.route_new_work(request),
    );

    assert_eq!(left.unwrap(), right.unwrap());
    assert_eq!(harness.row_count("runtime_bindings"), 1);
    assert_eq!(harness.row_count("routing_dispatch_intents"), 1);
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 0);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn accepted_binding_stays_source_after_routing_head_switch() {
    let harness = RoutingHarness::new(source_snapshot(8), VerifiedFeatureRegistry::default());
    let request = route_request();
    let first = harness
        .router
        .route_new_work(request.clone())
        .await
        .unwrap();

    let mut next = candidate_snapshot();
    next.routing_generation = RoutingGeneration::new(9).unwrap();
    next.fencing_token = FencingToken::new([9; 32]).unwrap();
    next.committed_at = Timestamp::from_unix_micros(30);
    harness.replace_head(next);
    let retry = harness.router.route_new_work(request).await.unwrap();

    assert_eq!(retry, first);
    assert!(matches!(
        retry.binding.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 1);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn stale_fence_creates_no_binding_and_dispatches_nowhere() {
    let snapshot = candidate_snapshot();
    let stale_registry = matching_registry();
    let harness = RoutingHarness::new_with_fence(
        snapshot,
        stale_registry,
        FencingToken::new([9; 32]).unwrap(),
    );

    let result = harness.router.route_new_work(route_request()).await;

    assert!(matches!(result, Err(MigrationRoutingError::Fence(_))));
    assert_eq!(harness.row_count("runtime_bindings"), 0);
    assert_eq!(harness.row_count("routing_dispatch_intents"), 0);
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 0);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn indeterminate_candidate_dispatch_never_falls_back_to_source() {
    let harness = RoutingHarness::new_with_attempt(
        candidate_snapshot(),
        matching_registry(),
        DispatchAttempt::Indeterminate,
    );
    let request = route_request();

    assert_eq!(
        harness.router.route_new_work(request.clone()).await,
        Err(MigrationRoutingError::ReconciliationRequired)
    );
    assert_eq!(
        harness.router.route_new_work(request).await,
        Err(MigrationRoutingError::ReconciliationRequired)
    );
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 0);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn unsupported_candidate_profile_uses_only_explicit_source_fallback_route() {
    let harness = RoutingHarness::new_with_fallback(
        candidate_snapshot(),
        VerifiedFeatureRegistry::default(),
        PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
            source_profile: routing_unit().feature_profile,
        },
    );

    let decision = harness
        .router
        .route_new_work(route_request())
        .await
        .unwrap();

    assert!(matches!(
        decision.binding.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 1);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn candidate_failure_after_acceptance_never_falls_back_to_source() {
    let harness = RoutingHarness::new_with_attempt(
        candidate_snapshot(),
        matching_registry(),
        DispatchAttempt::AcceptedThenFailed,
    );

    assert_eq!(
        harness.router.route_new_work(route_request()).await,
        Err(MigrationRoutingError::ReconciliationRequired)
    );
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 0);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn legacy_admission_closed_rejects_every_new_legacy_binding() {
    let harness = RoutingHarness::new_with_policies(
        candidate_snapshot(),
        matching_registry(),
        PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
            source_profile: routing_unit().feature_profile,
        },
        LegacyAdmissionPolicy::Closed,
    );
    let before = harness.row_count("runtime_bindings");
    let mut request = route_request();
    request.authority_preference = RouteAuthorityPreference::LegacySource;

    assert_eq!(
        harness.router.route_new_work(request).await,
        Err(MigrationRoutingError::LegacyAdmissionClosed)
    );
    assert_eq!(harness.row_count("runtime_bindings"), before);
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 0);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn existing_legacy_binding_remains_pinned_during_deprecation() {
    let snapshot = source_snapshot(8);
    let harness = RoutingHarness::new_with_policies(
        snapshot.clone(),
        VerifiedFeatureRegistry::default(),
        PreDispatchFallbackPolicy::Disabled,
        LegacyAdmissionPolicy::Closed,
    );
    harness
        .store
        .bind_and_create_dispatch_intent(BindRuntimeRequest {
            aggregate_id: AggregateId::TaskRun(taskrun_id()),
            routing_unit: routing_unit(),
            expected_snapshot: snapshot,
            fallback_policy: PreDispatchFallbackPolicy::Disabled,
            command_id: command_id(),
            idempotency_key: IdempotencyKey::new("migration-route-1").unwrap(),
            request_digest: ArtifactDigest::from_bytes([11; 32]),
            bound_at: Timestamp::from_unix_micros(20),
        })
        .unwrap();

    let decision = harness
        .router
        .route_new_work(route_request())
        .await
        .unwrap();

    assert!(matches!(
        decision.binding.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(harness.dispatch.source.load(Ordering::Acquire), 1);
    assert_eq!(harness.dispatch.candidate.load(Ordering::Acquire), 0);
}

struct RoutingHarness {
    db: TestDb,
    store: Arc<SqliteMigrationControlStore>,
    router:
        MigrationRouter<SqliteMigrationControlStore, FenceRegistry, CountingDispatch, FixedClock>,
    dispatch: Arc<CountingDispatch>,
}
