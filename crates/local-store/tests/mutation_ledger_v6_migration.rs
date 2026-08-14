#![cfg(feature = "test-support")]

use gocode_local_store::{
    LocalStore, MutationIdentity, MutationOperation, MutationTargetKind,
    security_v6_test_support::downgrade_with_active_rows,
};
use gocode_secure_store::test_support::DeterministicSecureStore;

type Tombstone = (String, Option<Vec<u8>>, Option<Vec<u8>>, i64, String);

#[test]
fn populated_v6_rows_migrate_once_to_manual_tombstones() {
    let directory = tempfile::tempdir().unwrap();
    let profile = [96; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    let keys = downgrade_with_active_rows(&mut store, &secure).unwrap();
    drop(store);
    let mut migrated = LocalStore::open_anchored(&path, &secure, profile).unwrap();
    for key in &keys {
        let identity = identity(key);
        let result = migrated.prepare_anchored_mutation(&secure, identity);
        assert!(result.is_err(), "legacy rows cannot resend");
    }
    let rows: Vec<Tombstone> = rusqlite::Connection::open(&path).unwrap()
        .prepare("SELECT client_disposition,normalized_command,canonical_outcome,resend_count,recovery_summary FROM mutation_ledger ORDER BY idempotency_key").unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).unwrap()
        .collect::<Result<_, _>>().unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.into_iter().all(|row| row
        == (
            "manual_resolution".into(),
            None,
            None,
            0,
            "v6_unrecoverable".into()
        )));
    drop(migrated);
    LocalStore::open_anchored(&path, &secure, profile).unwrap();
}

fn identity(key: &str) -> MutationIdentity {
    MutationIdentity::new(
        [1; 32],
        [2; 32],
        MutationOperation::ProjectCreate,
        MutationTargetKind::Project,
        gocode_local_store::BoundedCanonicalId::parse(b"018f2e3a-7000-7000-8000-000000000096")
            .unwrap(),
        key,
        0,
        [3; 32],
    )
    .unwrap()
}
