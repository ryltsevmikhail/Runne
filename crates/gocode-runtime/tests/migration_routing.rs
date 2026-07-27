use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use gocode_application::{
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
use gocode_domain::{
    id::{AggregateId, CommandId, IdempotencyKey, TaskRunId},
    timestamp::Timestamp,
};
use gocode_platform::fence::FenceRegistry;
use gocode_runtime::{
    migration_fence::MigrationFenceGuard,
    migration_router::{
        DispatchAttempt, LegacyAdmissionPolicy, MigrationDispatchPort, MigrationRouter,
        MigrationRoutingError, RouteAuthorityPreference, RouteNewWorkRequest,
    },
};
use gocode_store::{
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

impl RoutingHarness {
    fn new(snapshot: RoutingSnapshot, registry: VerifiedFeatureRegistry) -> Self {
        Self::new_with_fence_and_attempt(
            snapshot,
            registry,
            FencingToken::new([8; 32]).unwrap(),
            DispatchAttempt::Accepted,
        )
    }

    fn new_with_attempt(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        attempt: DispatchAttempt,
    ) -> Self {
        Self::new_with_fence_and_attempt(
            snapshot,
            registry,
            FencingToken::new([8; 32]).unwrap(),
            attempt,
        )
    }

    fn new_with_fence(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        active_token: FencingToken,
    ) -> Self {
        Self::new_with_fence_and_attempt(
            snapshot,
            registry,
            active_token,
            DispatchAttempt::Accepted,
        )
    }

    fn new_with_fallback(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        fallback_policy: PreDispatchFallbackPolicy,
    ) -> Self {
        Self::new_with_fence_attempt_and_fallback(
            snapshot,
            registry,
            FencingToken::new([8; 32]).unwrap(),
            DispatchAttempt::Accepted,
            fallback_policy,
        )
    }

    fn new_with_policies(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        fallback_policy: PreDispatchFallbackPolicy,
        legacy_admission_policy: LegacyAdmissionPolicy,
    ) -> Self {
        Self::new_with_fence_attempt_and_policies(
            snapshot,
            registry,
            FencingToken::new([8; 32]).unwrap(),
            DispatchAttempt::Accepted,
            fallback_policy,
            legacy_admission_policy,
        )
    }

    fn new_with_fence_and_attempt(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        active_token: FencingToken,
        attempt: DispatchAttempt,
    ) -> Self {
        Self::new_with_fence_attempt_and_fallback(
            snapshot,
            registry,
            active_token,
            attempt,
            PreDispatchFallbackPolicy::Disabled,
        )
    }

    fn new_with_fence_attempt_and_fallback(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        active_token: FencingToken,
        attempt: DispatchAttempt,
        fallback_policy: PreDispatchFallbackPolicy,
    ) -> Self {
        Self::new_with_fence_attempt_and_policies(
            snapshot,
            registry,
            active_token,
            attempt,
            fallback_policy,
            LegacyAdmissionPolicy::Open,
        )
    }

    fn new_with_fence_attempt_and_policies(
        snapshot: RoutingSnapshot,
        registry: VerifiedFeatureRegistry,
        active_token: FencingToken,
        attempt: DispatchAttempt,
        fallback_policy: PreDispatchFallbackPolicy,
        legacy_admission_policy: LegacyAdmissionPolicy,
    ) -> Self {
        let db = TestDb::new("runtime");
        let store = Arc::new(SqliteMigrationControlStore::open(db.path()).unwrap());
        seed_routing_head(db.path(), &routing_unit(), &snapshot);
        let fence = Arc::new(FenceRegistry::new(
            snapshot.routing_generation,
            active_token,
        ));
        let dispatch = Arc::new(CountingDispatch {
            fence: Arc::clone(&fence),
            source: AtomicUsize::new(0),
            candidate: AtomicUsize::new(0),
            attempt,
        });
        let router = MigrationRouter::new_with_routing_policies(
            Arc::clone(&store),
            Arc::new(registry),
            MigrationFenceGuard::new(fence),
            Arc::clone(&dispatch),
            Arc::new(FixedClock),
            fallback_policy,
            legacy_admission_policy,
        );
        Self {
            db,
            store,
            router,
            dispatch,
        }
    }

    fn replace_head(&self, snapshot: RoutingSnapshot) {
        let connection = Connection::open(self.db.path()).unwrap();
        let blob = encode_routing_snapshot(&snapshot).unwrap();
        connection
            .execute(
                "INSERT INTO routing_snapshots
                 (routing_unit_digest, routing_generation, snapshot_blob, committed_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    routing_unit().digest().as_bytes().as_slice(),
                    i64::try_from(snapshot.routing_generation.get()).unwrap(),
                    blob,
                    snapshot.committed_at.as_unix_micros(),
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE routing_head
                 SET routing_generation = ?1
                 WHERE routing_unit_digest = ?2",
                params![
                    i64::try_from(snapshot.routing_generation.get()).unwrap(),
                    routing_unit().digest().as_bytes().as_slice(),
                ],
            )
            .unwrap();
    }

    fn row_count(&self, table: &str) -> i64 {
        let connection = Connection::open(self.db.path()).unwrap();
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp, ClockError> {
        Ok(Timestamp::from_unix_micros(20))
    }
}

struct CountingDispatch {
    fence: Arc<FenceRegistry>,
    source: AtomicUsize,
    candidate: AtomicUsize,
    attempt: DispatchAttempt,
}

impl MigrationDispatchPort for CountingDispatch {
    async fn dispatch(&self, binding: RuntimeBinding, _command_id: CommandId) -> DispatchAttempt {
        self.fence
            .authorize_dispatch(
                binding.routing_generation,
                binding.fencing_token,
                || match binding.authority {
                    RuntimeAuthority::Source(_) => {
                        self.source.fetch_add(1, Ordering::AcqRel);
                    }
                    RuntimeAuthority::Candidate(_) => {
                        self.candidate.fetch_add(1, Ordering::AcqRel);
                    }
                },
            )
            .map_or(DispatchAttempt::Indeterminate, |_| self.attempt)
    }
}

fn route_request() -> RouteNewWorkRequest {
    RouteNewWorkRequest {
        aggregate_id: AggregateId::TaskRun(taskrun_id()),
        routing_unit: routing_unit(),
        feature_request: feature_request(),
        command_id: command_id(),
        idempotency_key: IdempotencyKey::new("migration-route-1").unwrap(),
        request_digest: ArtifactDigest::from_bytes([11; 32]),
        authority_preference: RouteAuthorityPreference::Current,
    }
}

fn matching_registry() -> VerifiedFeatureRegistry {
    let request = feature_request();
    let mut registry = VerifiedFeatureRegistry::default();
    registry
        .insert(ReleaseFeatureClaim {
            runtime_release: request.runtime_release.clone(),
            platform: request.platform.clone(),
            source_baseline_sha: request.source_baseline_sha.clone(),
            feature_profile: request.feature_profile.clone(),
            contract_digest: request.contract_digest,
            schema_digest: request.schema_digest,
            profile_digest: request.profile_digest,
            mapping_digest: request.mapping_digest,
            config_digest: request.config_digest,
            status: FeatureStatus::Verified,
            evidence_digest: ArtifactDigest::from_bytes([12; 32]),
        })
        .unwrap();
    registry
}

fn feature_request() -> FeatureClaimRequest {
    FeatureClaimRequest {
        runtime_release: "candidate-v1".into(),
        platform: PlatformTuple {
            os: PlatformOs::MacOs,
            architecture: PlatformArchitecture::Aarch64,
            filesystem: FilesystemClass::LocalDurable,
            vfs: PlatformVfs::AppleFullFsync,
            process_model: ProcessModel::Sandboxed,
            sandbox_profile_digest: ArtifactDigest::from_bytes([13; 32]),
        },
        source_baseline_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
        feature_profile: routing_unit().feature_profile,
        contract_digest: ArtifactDigest::from_bytes([4; 32]),
        schema_digest: ArtifactDigest::from_bytes([5; 32]),
        profile_digest: ArtifactDigest::from_bytes([6; 32]),
        mapping_digest: ArtifactDigest::from_bytes([7; 32]),
        config_digest: ArtifactDigest::from_bytes([8; 32]),
    }
}

fn candidate_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(8).unwrap(),
        RuntimeGenerationRef::new("source-v1").unwrap(),
        RuntimeGenerationRef::new("candidate-v1").unwrap(),
        gocode_application::migration::state::MigrationPhase::InternalCanary,
        RuntimeAuthority::Candidate(RuntimeGenerationRef::new("candidate-v1").unwrap()),
        routing_unit(),
        FencingToken::new([8; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(10),
    )
    .unwrap()
}

fn source_snapshot(generation: u64) -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(generation).unwrap(),
        RuntimeGenerationRef::new("source-v1").unwrap(),
        RuntimeGenerationRef::new("candidate-v1").unwrap(),
        gocode_application::migration::state::MigrationPhase::InternalCanary,
        RuntimeAuthority::Source(RuntimeGenerationRef::new("source-v1").unwrap()),
        routing_unit(),
        FencingToken::new([8; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(10),
    )
    .unwrap()
}

fn routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "premium").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("taskrun", 1, ArtifactDigest::from_bytes([3; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([4; 32]),
        schema_digest: ArtifactDigest::from_bytes([5; 32]),
        config_digest: ArtifactDigest::from_bytes([8; 32]),
    }
}

fn seed_routing_head(path: &Path, unit: &RoutingUnit, snapshot: &RoutingSnapshot) {
    let connection = Connection::open(path).unwrap();
    let blob = encode_routing_snapshot(snapshot).unwrap();
    connection
        .execute(
            "INSERT INTO routing_snapshots
             (routing_unit_digest, routing_generation, snapshot_blob, committed_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                unit.digest().as_bytes().as_slice(),
                i64::try_from(snapshot.routing_generation.get()).unwrap(),
                blob,
                snapshot.committed_at.as_unix_micros(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO routing_head (routing_unit_digest, routing_generation)
             VALUES (?1, ?2)",
            params![
                unit.digest().as_bytes().as_slice(),
                i64::try_from(snapshot.routing_generation.get()).unwrap(),
            ],
        )
        .unwrap();
}

fn taskrun_id() -> TaskRunId {
    "018f2e3a-8d5c-7b20-8d9a-000000000101".parse().unwrap()
}

fn command_id() -> CommandId {
    "018f2e3a-8d5c-7b20-8d9a-000000000102".parse().unwrap()
}

struct TestDb {
    path: PathBuf,
}

impl TestDb {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "gocode-runtime-routing-{label}-{}-{}.sqlite",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.path.display(), suffix));
        }
    }
}
