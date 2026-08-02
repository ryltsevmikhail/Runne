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
