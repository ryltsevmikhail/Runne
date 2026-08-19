use runne_local_store::{
    BoundedCanonicalId, ClientMutationDisposition, LocalStore, MutationIdentity, MutationOperation,
    MutationRecoveryBinding, MutationRecoveryLimit, MutationTargetKind, NormalizedMutationCommand,
    V7MutationTransition,
};
use runne_secure_store::test_support::DeterministicSecureStore;

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000081";

#[test]
fn anchored_recovery_reopens_exact_nonterminal_evidence_in_order_without_writes() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [81; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    prepare(&mut store, &secure, "z-key", [1; 32], [2; 32], 1);
    prepare(&mut store, &secure, "a-key", [1; 32], [2; 32], 2);
    let before = root(&path);
    drop(store);

    let mut reopened = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let binding = MutationRecoveryBinding::new([1; 32], [2; 32]).unwrap();
    assert!(MutationRecoveryLimit::new(0).is_err());
    assert!(MutationRecoveryLimit::new(65).is_err());
    let batch = reopened
        .recover_anchored_mutations_v7(&secure, binding, MutationRecoveryLimit::new(1).unwrap())
        .unwrap();
    assert!(batch.has_more());
    assert_eq!(batch.records().len(), 1);
    let evidence = &batch.records()[0];
    assert_eq!(evidence.idempotency_key(), "a-key");
    assert_eq!(evidence.operation(), MutationOperation::ProjectCreate);
    assert_eq!(
        evidence.target().canonical_id().as_bytes(),
        PROJECT.as_bytes()
    );
    assert_eq!(evidence.expected_version(), 0);
    assert_eq!(evidence.semantic_digest(), [2; 32]);
    assert_eq!(evidence.disposition(), ClientMutationDisposition::Prepared);
    assert_eq!(
        evidence.normalized_command(),
        &NormalizedMutationCommand::create_project(id(), "Project 2".into()).unwrap()
    );
    assert_eq!(root(&path), before);
}

#[test]
fn anchored_recovery_lookup_isolated_by_runtime_and_principal_and_excludes_terminals() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [82; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    prepare(&mut store, &secure, "visible", [3; 32], [4; 32], 3);
    let terminal = identity("terminal", [3; 32], [4; 32], 4);
    store
        .prepare_anchored_mutation_v7(
            &secure,
            terminal.clone(),
            NormalizedMutationCommand::create_project(id(), "Terminal".into()).unwrap(),
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            terminal,
            V7MutationTransition::Dispatching { timestamp: 1 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity("terminal", [3; 32], [4; 32], 4),
            V7MutationTransition::Indeterminate { timestamp: 2 },
        )
        .unwrap();
    store
        .transition_anchored_mutation_v7(
            &secure,
            identity("terminal", [3; 32], [4; 32], 4),
            V7MutationTransition::ManualResolution {
                summary: "closed".into(),
                timestamp: 3,
            },
        )
        .unwrap();

    let binding = MutationRecoveryBinding::new([3; 32], [4; 32]).unwrap();
    assert!(
        store
            .lookup_anchored_mutation_recovery_v7(&secure, binding, "visible")
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .lookup_anchored_mutation_recovery_v7(
                &secure,
                MutationRecoveryBinding::new([5; 32], [4; 32]).unwrap(),
                "visible",
            )
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .lookup_anchored_mutation_recovery_v7(
                &secure,
                MutationRecoveryBinding::new([3; 32], [5; 32]).unwrap(),
                "visible",
            )
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .lookup_anchored_mutation_recovery_v7(
                &secure,
                MutationRecoveryBinding::new([3; 32], [4; 32]).unwrap(),
                "terminal",
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn recovery_reopens_verified_one_ahead_state_and_rejects_corrupt_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [83; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let identity = identity("one-ahead", [6; 32], [7; 32], 5);
    store
        .prepare_anchored_mutation_v7(
            &secure,
            identity.clone(),
            NormalizedMutationCommand::create_project(id(), "Project 5".into()).unwrap(),
        )
        .unwrap();
    secure.fail_next_advance();
    assert!(
        store
            .transition_anchored_mutation_v7(
                &secure,
                identity,
                V7MutationTransition::Dispatching { timestamp: 1 },
            )
            .is_err()
    );
    drop(store);

    let mut reopened = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    assert_eq!(
        reopened
            .lookup_anchored_mutation_recovery_v7(
                &secure,
                MutationRecoveryBinding::new([6; 32], [7; 32]).unwrap(),
                "one-ahead",
            )
            .unwrap()
            .unwrap()
            .disposition(),
        ClientMutationDisposition::Dispatching
    );
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE mutation_ledger SET normalized_command=x'00' WHERE idempotency_key='one-ahead'",
            [],
        )
        .unwrap();
    assert!(
        reopened
            .lookup_anchored_mutation_recovery_v7(
                &secure,
                MutationRecoveryBinding::new([6; 32], [7; 32]).unwrap(),
                "one-ahead",
            )
            .is_err()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn recovery_never_returns_migrated_v6_manual_tombstones() {
    use runne_local_store::security_v6_test_support::downgrade_with_active_rows;

    let directory = tempfile::tempdir().unwrap();
    let profile = [84; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    downgrade_with_active_rows(&mut store, &secure).unwrap();
    drop(store);

    let mut migrated = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let batch = migrated
        .recover_anchored_mutations_v7(
            &secure,
            MutationRecoveryBinding::new([1; 32], [2; 32]).unwrap(),
            MutationRecoveryLimit::new(64).unwrap(),
        )
        .unwrap();
    assert!(batch.records().is_empty());
    assert!(!batch.has_more());
}

fn prepare(
    store: &mut LocalStore,
    secure: &DeterministicSecureStore,
    key: &str,
    runtime: [u8; 32],
    principal: [u8; 32],
    number: u8,
) {
    store
        .prepare_anchored_mutation_v7(
            secure,
            identity(key, runtime, principal, number),
            NormalizedMutationCommand::create_project(id(), format!("Project {number}")).unwrap(),
        )
        .unwrap();
}

fn identity(key: &str, runtime: [u8; 32], principal: [u8; 32], semantic: u8) -> MutationIdentity {
    MutationIdentity::new(
        runtime,
        principal,
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        id(),
        key,
        0,
        [semantic; 32],
    )
    .unwrap()
}

fn id() -> BoundedCanonicalId {
    BoundedCanonicalId::parse(PROJECT.as_bytes()).unwrap()
}

fn root(path: &std::path::Path) -> (i64, String, i64) {
    rusqlite::Connection::open(path).unwrap().query_row(
        "SELECT db_generation,last_transaction_digest,(SELECT COUNT(*) FROM security_transactions) FROM meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap()
}
