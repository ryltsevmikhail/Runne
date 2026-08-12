#![allow(clippy::format_collect)]

use gocode_local_store::LocalStore;
use gocode_secure_store::{
    SecureStore, SecurityAnchorV1, StoredSecurityAnchor, test_support::DeterministicSecureStore,
};
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
    drop(LocalStore::open_anchored(&path, &secure_store, profile).expect("genesis"));
    let database: Vec<u8> = Connection::open(&path)
        .expect("database")
        .query_row(
            "SELECT database_identity FROM security_profile WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("identity");
    let database: [u8; 32] = database.try_into().expect("identity width");
    let lock = secure_store
        .acquire_security_profile_lock(profile)
        .expect("profile lock");
    let StoredSecurityAnchor::V1(current) =
        secure_store.read_security_anchor(&lock).expect("anchor")
    else {
        panic!("expected V1 anchor");
    };
    let digest = [42; 32];
    let seal = secure_store
        .seal_security_transaction(&lock, database, 2, digest, current.digest())
        .expect("seal");
    let next =
        SecurityAnchorV1::new(profile, database, 2, digest, current.digest(), seal).expect("next");
    drop(lock);
    let mut database_connection = Connection::open(&path).expect("database");
    let transaction = database_connection.transaction().expect("transaction");
    transaction
        .execute(
            "INSERT INTO security_transactions VALUES (2,?1,?2,?3,1)",
            rusqlite::params![
                next.transaction_digest.to_vec(),
                next.previous_anchor_digest.to_vec(),
                next.sealed_transaction.as_bytes()
            ],
        )
        .expect("persisted seal");
    transaction
        .execute(
            "UPDATE meta SET db_generation=2,last_transaction_digest=?1,commit_marker=1",
            [hex(&digest)],
        )
        .expect("one ahead");
    transaction.commit().expect("commit");
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

fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
