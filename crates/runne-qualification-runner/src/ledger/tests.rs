#[path = "tests/crash.rs"]
mod crash;
#[path = "tests/fixture.rs"]
mod fixture;

use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::sync::{Arc, Barrier};

use tempfile::TempDir;

use super::QualificationReplayLedger;
use crate::CanonicalRunBinding;

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn binding(manifest: u8, profile: u8) -> CanonicalRunBinding {
    CanonicalRunBinding::new([manifest; 32], [profile; 32]).expect("nonzero binding")
}

fn private_root() -> TempDir {
    let root =
        TempDir::new_in(std::fs::canonicalize(std::env::temp_dir()).expect("canonical temp"))
            .expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    root
}

fn open(root: &TempDir) -> QualificationReplayLedger {
    QualificationReplayLedger::open_for_test(root.path(), uid()).expect("private test ledger")
}

#[test]
fn fault_record_is_durable_across_reopen_and_lost_ack() {
    let root = private_root();
    let facts = fixture::facts([1, 2, 3, 4]);
    open(&root)
        .consume_fault(facts, binding(5, 6))
        .expect("first durable consume");
    assert!(
        open(&root)
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .is_err(),
        "a committed record remains consumed if acknowledgement is lost"
    );
}

#[test]
fn every_context_and_ticket_identity_is_independently_single_use() {
    let root = private_root();
    open(&root)
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .expect("baseline consume");
    for duplicate in [[1, 7, 8, 9], [7, 2, 8, 9], [7, 8, 3, 9], [7, 8, 9, 4]] {
        assert!(
            open(&root)
                .consume_fault(fixture::facts(duplicate), binding(5, 6))
                .is_err(),
            "each replay key is independently protected"
        );
    }
}

#[test]
fn immutable_run_rejects_rebinding_but_allows_distinct_fault_cases() {
    let root = private_root();
    let mut ledger = open(&root);
    ledger
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .expect("first case");
    ledger
        .consume_fault(fixture::facts([7, 8, 9, 10]), binding(5, 6))
        .expect("distinct case for same immutable run");
    assert!(
        open(&root)
            .consume_fault(fixture::facts([11, 12, 13, 14]), binding(15, 6))
            .is_err(),
        "manifest/profile cannot rebind an existing source/run/namespace"
    );
}

#[test]
fn concurrent_consumers_serialize_distinct_cases() {
    let root = Arc::new(private_root());
    drop(open(&root));
    let barrier = Arc::new(Barrier::new(4));
    let joins = (0_u8..4)
        .map(|offset| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                QualificationReplayLedger::open_for_test(root.path(), uid())?.consume_fault(
                    fixture::facts([20 + offset, 30 + offset, 40 + offset, 50 + offset]),
                    binding(5, 6),
                )
            })
        })
        .collect::<Vec<_>>();
    for join in joins {
        assert!(join.join().expect("thread").is_ok());
    }
}

#[allow(clippy::needless_collect)]
#[test]
fn concurrent_same_case_has_exactly_one_durable_winner() {
    let root = Arc::new(private_root());
    drop(open(&root));
    let barrier = Arc::new(Barrier::new(4));
    let joins = (0..4)
        .map(|_| {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                QualificationReplayLedger::open_for_test(root.path(), uid())?
                    .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        joins
            .into_iter()
            .map(|join| join.join().expect("thread").is_ok())
            .filter(|result| *result)
            .count(),
        1
    );
}

#[test]
fn conflicting_later_replay_key_rolls_back_earlier_new_keys() {
    let root = private_root();
    open(&root)
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .expect("baseline consume");
    assert!(open(&root)
        .consume_fault(fixture::facts([5, 6, 3, 7]), binding(5, 6))
        .is_err());
    open(&root)
        .consume_fault(fixture::facts([5, 6, 7, 8]), binding(5, 6))
        .expect("rolled-back context keys remain unused");
}

#[test]
fn schema_and_pragma_uncertainty_close_the_ledger() {
    let root = private_root();
    let mut ledger = open(&root);
    ledger
        .connection
        .execute_batch("PRAGMA synchronous=OFF")
        .expect("test downgrade");
    assert!(ledger
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .is_err());
    assert!(ledger
        .consume_fault(fixture::facts([7, 8, 9, 10]), binding(5, 6))
        .is_err());
    drop(ledger);
    let path = root.path().join(crate::path_guard::DATABASE_NAME);
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("UPDATE ledger_meta SET schema_id='wrong'", [])
        .expect("corrupt schema");
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
}

#[test]
fn existing_empty_database_is_not_initialized_as_a_new_ledger() {
    let root = private_root();
    std::fs::write(root.path().join(crate::path_guard::DATABASE_NAME), []).expect("empty db");
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
}

#[test]
fn schema_or_semantic_replay_tampering_rejects_reopen() {
    let root = private_root();
    open(&root)
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .expect("baseline consume");
    let path = root.path().join(crate::path_guard::DATABASE_NAME);
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("DELETE FROM replay_keys WHERE domain=1", [])
        .expect("remove key");
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());

    let second = private_root();
    drop(open(&second));
    let path = second.path().join(crate::path_guard::DATABASE_NAME);
    rusqlite::Connection::open(&path)
        .expect("database")
        .execute("CREATE VIEW unexpected AS SELECT 1", [])
        .expect("unexpected view");
    assert!(QualificationReplayLedger::open_for_test(second.path(), uid()).is_err());

    let third = private_root();
    drop(open(&third));
    let path = third.path().join(crate::path_guard::DATABASE_NAME);
    let raw = rusqlite::Connection::open(&path).expect("database");
    raw.execute_batch("PRAGMA writable_schema=ON; INSERT INTO sqlite_schema(type, name, tbl_name, rootpage, sql) VALUES ('trigger', 'sqlite_evil', 'fault_cases', 0, 'CREATE TRIGGER sqlite_evil AFTER INSERT ON fault_cases BEGIN DELETE FROM replay_keys; END'); PRAGMA schema_version=99; PRAGMA writable_schema=OFF;")
        .expect("reserved trigger");
    assert!(QualificationReplayLedger::open_for_test(third.path(), uid()).is_err());

    let associated = private_root();
    open(&associated)
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .expect("baseline consume");
    let path = associated.path().join(crate::path_guard::DATABASE_NAME);
    let raw = rusqlite::Connection::open(&path).expect("database");
    raw.execute_batch("INSERT INTO immutable_runs SELECT source_revision, 'other-run', namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs; UPDATE replay_keys SET workflow_run_id='other-run' WHERE domain=1;")
        .expect("rebind key association");
    assert!(QualificationReplayLedger::open_for_test(associated.path(), uid()).is_err());
}

#[test]
fn failed_directory_or_database_sync_refuses_the_new_ledger() {
    let root = private_root();
    crate::path_guard::fail_next_sync();
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
}

#[test]
fn private_path_guards_reject_symlinks_hardlinks_modes_and_owner_mismatch() {
    let target = TempDir::new().expect("target");
    let root = TempDir::new().expect("root");
    let link = root.path().join("link");
    symlink(target.path(), &link).expect("symlink");
    assert!(QualificationReplayLedger::open_for_test(&link, uid()).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());

    let symlink_database_root = private_root();
    symlink(
        target.path().join("missing.sqlite3"),
        symlink_database_root
            .path()
            .join(crate::path_guard::DATABASE_NAME),
    )
    .expect("database symlink");
    assert!(QualificationReplayLedger::open_for_test(symlink_database_root.path(), uid()).is_err());

    let database_root = private_root();
    drop(open(&database_root));
    let database = database_root.path().join(crate::path_guard::DATABASE_NAME);
    std::fs::hard_link(&database, database_root.path().join("second")).expect("hard link");
    assert!(QualificationReplayLedger::open_for_test(database_root.path(), uid()).is_err());
    assert!(QualificationReplayLedger::open_for_test(
        database_root.path(),
        uid().saturating_add(1)
    )
    .is_err());
}
