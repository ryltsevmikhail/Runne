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
