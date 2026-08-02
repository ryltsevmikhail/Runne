use std::{
    fs,
    path::{Path, PathBuf},
};

use gocode_application::migration::{
    ports::MigrationStoreError,
    rollout::PreDispatchFallbackPolicy,
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
fn explicit_pre_dispatch_fallback_binds_source_atomically() {
    let db = TestDb::new("source-fallback");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let mut request = bind_request(snapshot);
    request.fallback_policy = PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
        source_profile: routing_unit().feature_profile,
    };

    let admission = store.bind_and_create_dispatch_intent(request).unwrap();

    assert!(matches!(
        admission.binding().authority,
        RuntimeAuthority::Source(ref generation)
            if generation == &RuntimeGenerationRef::new("source-v1").unwrap()
    ));
    assert_eq!(admission.intent().status, DispatchIntentStatus::Pending);
}

#[test]
fn mismatched_fallback_profile_mutates_nothing() {
    let db = TestDb::new("mismatched-fallback");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let snapshot = candidate_snapshot();
    seed_routing_head(db.path(), &routing_unit(), &snapshot);
    let aggregate_id = AggregateId::TaskRun(taskrun_id());
    let mut request = bind_request(snapshot);
    request.fallback_policy = PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
        source_profile: FeatureProfileRef::new("other", 1, ArtifactDigest::from_bytes([99; 32]))
            .unwrap(),
    };

    assert_eq!(
        store.bind_and_create_dispatch_intent(request),
        Err(MigrationStoreError::IntegrityViolation)
    );
    assert_eq!(
        store
            .load_runtime_binding(aggregate_id.clone(), &routing_unit())
            .unwrap(),
        None
    );
    assert_eq!(store.load_dispatch_intent(aggregate_id).unwrap(), None);
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
