#![allow(clippy::format_collect)]

use runne_local_store::LocalStore;
use runne_secure_store::test_support::DeterministicSecureStore;
use rusqlite::Connection;

#[test]
fn security_state_open_admits_only_a_new_missing_anchor_profile() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [7; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    let result = LocalStore::open_anchored(
        &directory.path().join("profile.sqlite3"),
        &secure_store,
        profile,
    );
    if let Err(error) = result {
        panic!("genesis admission: {error:?}");
    }
}

#[test]
fn security_state_open_migrates_only_an_empty_exact_v5_legacy_anchor() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    LocalStore::open(&path).expect("v5 profile");
    let profile = [8; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    secure_store.set_legacy_generation(1);
    LocalStore::open_anchored(&path, &secure_store, profile).expect("migrate legacy profile");
}

#[test]
fn security_state_open_resumes_a_committed_v6_legacy_migration_only_from_its_seal() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    LocalStore::open(&path).expect("v5 profile");
    let profile = [18; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    secure_store.set_legacy_generation(1);
    secure_store.fail_next_legacy_migration();
    assert!(LocalStore::open_anchored(&path, &secure_store, profile).is_err());
    LocalStore::open_anchored(&path, &secure_store, profile).expect("resume persisted migration");
}

#[test]
fn security_state_open_reopens_an_exact_v1_anchor() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    let profile = [9; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    drop(LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis"));
    LocalStore::open_anchored(&path, &secure_store, profile).expect("reopen v1");
}

#[test]
fn security_state_open_rejects_a_missing_anchor_for_an_existing_database() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    LocalStore::open(&path).expect("v5 profile");
    let profile = [10; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    assert!(LocalStore::open_anchored(&path, &secure_store, profile).is_err());
}

#[test]
fn security_state_open_rejects_a_forged_persisted_seal() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    let profile = [11; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    drop(LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis"));
    Connection::open(&path)
        .expect("database")
        .execute(
            "UPDATE security_transactions SET sealed_transaction = x'01'",
            [],
        )
        .expect("forge seal");
    assert!(LocalStore::open_anchored(&path, &secure_store, profile).is_err());
}

#[test]
fn security_state_open_rejects_a_generation_gap() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    let profile = [12; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    drop(LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis"));
    Connection::open(&path)
        .expect("database")
        .execute("UPDATE meta SET db_generation = 3", [])
        .expect("gap");
    assert!(LocalStore::open_anchored(&path, &secure_store, profile).is_err());
}

#[test]
fn security_state_open_recovers_only_a_verified_database_one_ahead() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    let profile = [13; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    let mut store = LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis");
    let identity = runne_local_store::MutationIdentity::new(
        [1; 32],
        [2; 32],
        runne_local_store::MutationOperation::ProjectCreate,
        runne_local_store::MutationTargetKind::Project,
        runne_local_store::BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000094")
            .expect("id"),
        "recovery",
        0,
        [3; 32],
    )
    .expect("identity");
    secure_store.fail_next_advance();
    assert!(
        store
            .prepare_anchored_mutation_v7(
                &secure_store,
                identity,
                project_command(b"018f2e3a-7000-7000-8000-000000000094"),
            )
            .is_err()
    );
    drop(store);
    LocalStore::open_anchored(&path, &secure_store, profile).expect("recover one ahead");
}

#[test]
fn security_state_open_rejects_changed_profile_or_database_binding() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let path = directory.path().join("profile.sqlite3");
    let profile = [14; 32];
    let secure_store = DeterministicSecureStore::new(profile);
    drop(LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis"));
    Connection::open(&path)
        .expect("database")
        .execute(
            "UPDATE security_profile SET database_identity=?1",
            [vec![99_u8; 32]],
        )
        .expect("tamper binding");
    assert!(LocalStore::open_anchored(&path, &secure_store, profile).is_err());
}

#[test]
fn security_state_open_rejects_every_ledger_column_tamper() {
    let updates = [
        "runtime_authority_digest=x'0909090909090909090909090909090909090909090909090909090909090909'",
        "principal_digest=x'0808080808080808080808080808080808080808080808080808080808080808'",
        "operation_kind='tampered'",
        "target_kind='tampered'",
        "target_id=x'74'",
        "idempotency_key='tampered'",
        "expected_version=1",
        "semantic_digest=x'0707070707070707070707070707070707070707070707070707070707070707'",
        "client_disposition='retryable'",
        "runtime_disposition='indeterminate'",
        "command_ref=x'04'",
        "outcome_ref=x'05'",
        "recovery_summary='tampered'",
        "created_at=1",
        "updated_at=1",
    ];
    for (index, update) in updates.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("temporary profile");
        let path = directory.path().join("profile.sqlite3");
        let profile = [40 + u8::try_from(index).expect("profile index"); 32];
        let secure = DeterministicSecureStore::new(profile);
        let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("genesis");
        let identity = runne_local_store::MutationIdentity::new(
            [1; 32],
            [2; 32],
            runne_local_store::MutationOperation::ProjectCreate,
            runne_local_store::MutationTargetKind::Project,
            runne_local_store::BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000095")
                .expect("id"),
            "tamper",
            0,
            [3; 32],
        )
        .expect("identity");
        store
            .prepare_anchored_mutation_v7(
                &secure,
                identity,
                project_command(b"018f2e3a-7000-7000-8000-000000000095"),
            )
            .expect("prepare");
        drop(store);
        let rejected_by_schema = Connection::open(&path)
            .expect("database")
            .execute(&format!("UPDATE mutation_ledger SET {update}"), [])
            .is_err();
        assert!(
            rejected_by_schema || LocalStore::open_anchored(&path, &secure, profile).is_err(),
            "{update}"
        );
    }
}

fn project_command(id: &[u8]) -> runne_local_store::NormalizedMutationCommand {
    runne_local_store::NormalizedMutationCommand::create_project(
        runne_local_store::BoundedCanonicalId::parse(id).unwrap(),
        "Project".into(),
    )
    .unwrap()
}
