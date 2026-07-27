use std::{
    fs,
    path::{Path, PathBuf},
};

use gocode_application::migration::{
    ports::MigrationStoreError,
    routing::{
        BindRuntimeRequest, DispatchClaim, DispatchIntentStatus, DispatchResultStatus,
        MigrationRoutingStore, RouteAdmission,
    },
    state::MigrationPhase,
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
        RuntimeAuthority, RuntimeGenerationRef,
    },
};
use gocode_domain::{
    id::{AggregateId, CommandId, IdempotencyKey, TaskRunId},
    timestamp::Timestamp,
};
use gocode_store::{
    migration_codec::{encode_routing_snapshot, encode_runtime_binding},
    migration_store::SqliteMigrationControlStore,
};
use rusqlite::{Connection, params};

#[test]
fn binding_and_pending_dispatch_intent_commit_atomically_and_replay_exactly() {
    let db = TestDb::new("binding-intent");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let request = bind_request(snapshot);

    let first = store
        .bind_and_create_dispatch_intent(request.clone())
        .unwrap();
    let retry = store.bind_and_create_dispatch_intent(request).unwrap();

    let RouteAdmission::Created { binding, intent } = first else {
        panic!("first admission must create the binding");
    };
    assert_eq!(
        retry,
        RouteAdmission::Existing {
            binding: binding.clone(),
            intent: intent.clone(),
        }
    );
    assert!(matches!(binding.authority, RuntimeAuthority::Candidate(_)));
    assert_eq!(intent.status, DispatchIntentStatus::Pending);
    assert_eq!(row_count(db.path(), "runtime_bindings"), 1);
    assert_eq!(row_count(db.path(), "routing_dispatch_intents"), 1);
}

#[test]
fn claimed_dispatch_is_indeterminate_before_external_effect_and_survives_reopen() {
    let db = TestDb::new("claim-reopen");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let request = bind_request(snapshot);
    store
        .bind_and_create_dispatch_intent(request.clone())
        .unwrap();

    let claim = store
        .claim_dispatch(
            request.aggregate_id.clone(),
            request.command_id,
            Timestamp::from_unix_micros(25),
        )
        .unwrap();
    let DispatchClaim::Claimed(claimed) = claim else {
        panic!("first claim must acquire dispatch authority");
    };
    assert_eq!(claimed.status, DispatchIntentStatus::Indeterminate);
    drop(store);

    let reopened = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(
        reopened
            .load_dispatch_intent(request.aggregate_id.clone())
            .unwrap()
            .unwrap(),
        claimed
    );
    assert_eq!(
        reopened
            .claim_dispatch(
                request.aggregate_id.clone(),
                request.command_id,
                Timestamp::from_unix_micros(26),
            )
            .unwrap(),
        DispatchClaim::Existing(claimed)
    );
}

#[test]
fn accepted_or_indeterminate_intent_cannot_be_automatically_reclaimed() {
    let db = TestDb::new("accepted");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let request = bind_request(snapshot);
    store
        .bind_and_create_dispatch_intent(request.clone())
        .unwrap();
    assert!(matches!(
        store
            .claim_dispatch(
                request.aggregate_id.clone(),
                request.command_id,
                Timestamp::from_unix_micros(25),
            )
            .unwrap(),
        DispatchClaim::Claimed(_)
    ));
    let accepted = store
        .record_dispatch_result(
            request.aggregate_id.clone(),
            request.command_id,
            DispatchResultStatus::Accepted,
            Timestamp::from_unix_micros(30),
        )
        .unwrap();

    assert_eq!(accepted.status, DispatchIntentStatus::Accepted);
    assert_eq!(
        store
            .claim_dispatch(
                request.aggregate_id.clone(),
                request.command_id,
                Timestamp::from_unix_micros(31),
            )
            .unwrap(),
        DispatchClaim::Existing(accepted)
    );
}

#[test]
fn dispatch_identity_conflict_rolls_back_new_binding_atomically() {
    let db = TestDb::new("intent-conflict-rollback");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let first = bind_request(snapshot.clone());
    store.bind_and_create_dispatch_intent(first).unwrap();
    let mut conflicting = bind_request(snapshot);
    conflicting.aggregate_id = AggregateId::TaskRun(second_taskrun_id());
    conflicting.idempotency_key = IdempotencyKey::new("route-taskrun-2").unwrap();

    assert_eq!(
        store.bind_and_create_dispatch_intent(conflicting.clone()),
        Err(MigrationStoreError::DispatchIntentConflict)
    );
    assert_eq!(row_count(db.path(), "runtime_bindings"), 1);
    assert_eq!(row_count(db.path(), "routing_dispatch_intents"), 1);
    assert_eq!(
        store
            .load_runtime_binding(conflicting.aggregate_id, &routing_unit())
            .unwrap(),
        None
    );
}

#[test]
fn binding_replay_rejects_snapshot_fence_mismatch() {
    let db = TestDb::new("binding-corruption");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let RouteAdmission::Created { mut binding, .. } = store
        .bind_and_create_dispatch_intent(bind_request(snapshot))
        .unwrap()
    else {
        panic!("first admission must create a binding");
    };
    binding.fencing_token = FencingToken::new([9; 32]).unwrap();
    let corrupted_blob = encode_runtime_binding(&binding).unwrap();
    Connection::open(db.path())
        .unwrap()
        .execute(
            "UPDATE runtime_bindings SET binding_blob = ?1",
            [corrupted_blob],
        )
        .unwrap();

    assert_eq!(
        store.load_runtime_binding(binding.aggregate_id, &routing_unit()),
        Err(MigrationStoreError::CorruptData)
    );
}

fn bind_request(snapshot: RoutingSnapshot) -> BindRuntimeRequest {
    BindRuntimeRequest {
        aggregate_id: AggregateId::TaskRun(taskrun_id()),
        routing_unit: routing_unit(),
        expected_snapshot: snapshot,
        command_id: command_id(),
        idempotency_key: IdempotencyKey::new("route-taskrun-1").unwrap(),
        request_digest: ArtifactDigest::from_bytes([11; 32]),
        bound_at: Timestamp::from_unix_micros(20),
    }
}

fn candidate_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(8).unwrap(),
        RuntimeGenerationRef::new("source-v1").unwrap(),
        RuntimeGenerationRef::new("candidate-v1").unwrap(),
        MigrationPhase::InternalCanary,
        RuntimeAuthority::Candidate(RuntimeGenerationRef::new("candidate-v1").unwrap()),
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

fn row_count(path: &Path, table: &str) -> i64 {
    let connection = Connection::open(path).unwrap();
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn taskrun_id() -> TaskRunId {
    "018f2e3a-8d5c-7b20-8d9a-000000000001".parse().unwrap()
}

fn command_id() -> CommandId {
    "018f2e3a-8d5c-7b20-8d9a-000000000002".parse().unwrap()
}

fn second_taskrun_id() -> TaskRunId {
    "018f2e3a-8d5c-7b20-8d9a-000000000003".parse().unwrap()
}

struct TestDb {
    path: PathBuf,
}

impl TestDb {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "gocode-routing-{label}-{}-{}.sqlite",
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
