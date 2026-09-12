use super::{binding, fixture, open, private_root, uid};
use crate::QualificationReplayLedger;

fn downgrade_fixture(root: &tempfile::TempDir) {
    let path = root.path().join(crate::path_guard::DATABASE_NAME);
    let connection = rusqlite::Connection::open(path).expect("fixture connection");
    connection.execute_batch("BEGIN IMMEDIATE; DROP TABLE run_bootstraps; UPDATE ledger_meta SET schema_id='runne/qualification-runner-replay/v1'; PRAGMA user_version=1; COMMIT;").expect("exact historical schema");
}

#[test]
fn historical_v1_upgrade_preserves_consumed_fault_keys() {
    let root = private_root();
    open(&root)
        .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
        .unwrap();
    downgrade_fixture(&root);
    let mut upgraded = open(&root);
    let version: i64 = upgraded
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
    assert!(
        upgraded
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .is_err()
    );
    drop(upgraded);
    open(&root)
        .consume_fault(fixture::facts([7, 8, 9, 10]), binding(5, 6))
        .unwrap();
}

#[test]
fn corrupted_v1_is_rejected_without_migration_or_erasure() {
    for mutation in [
        "DELETE FROM replay_keys WHERE domain=1",
        "INSERT INTO immutable_runs SELECT source_revision, 'orphan', namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs;",
        "CREATE VIEW unexpected AS SELECT 1",
        "UPDATE ledger_meta SET schema_id='wrong'",
    ] {
        let root = private_root();
        open(&root)
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .unwrap();
        downgrade_fixture(&root);
        let connection =
            rusqlite::Connection::open(root.path().join(crate::path_guard::DATABASE_NAME)).unwrap();
        connection.execute_batch(mutation).unwrap();
        assert!(QualificationReplayLedger::open_for_test(root.path(), uid()).is_err());
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let records: i64 = connection
            .query_row("SELECT COUNT(*) FROM fault_cases", [], |row| row.get(0))
            .unwrap();
        assert_eq!(records, 1);
    }
}

#[test]
fn concurrent_v1_openers_observe_one_valid_upgrade() {
    let root = std::sync::Arc::new(private_root());
    drop(open(&root));
    downgrade_fixture(&root);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let joins: Vec<_> = (0..4)
        .map(|_| {
            let root = std::sync::Arc::clone(&root);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                QualificationReplayLedger::open_for_test(root.path(), uid()).is_ok()
            })
        })
        .collect();
    for join in joins {
        assert!(join.join().unwrap());
    }
}

fn fault_snapshot(connection: &rusqlite::Connection) -> Vec<Vec<rusqlite::types::Value>> {
    let mut result = Vec::new();
    for table in ["immutable_runs", "replay_keys", "fault_cases"] {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap();
        result.extend(rows.map(Result::unwrap));
    }
    result
}

#[test]
fn migration_crash_boundaries_preserve_exact_fault_rows() {
    use std::os::unix::process::ExitStatusExt as _;
    for (boundary, expected_version) in [("before", 1), ("after", 2)] {
        let root = private_root();
        open(&root)
            .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
            .unwrap();
        downgrade_fixture(&root);
        let path = root.path().join(crate::path_guard::DATABASE_NAME);
        let before = fault_snapshot(&rusqlite::Connection::open(&path).unwrap());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ledger::tests::migration::migration_crash_child"])
            .env("RUNNE_TEST_LEDGER_MIGRATION_CRASH", boundary)
            .env("RUNNE_TEST_LEDGER_MIGRATION_ROOT", root.path())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(6));
        let connection = rusqlite::Connection::open(&path).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, expected_version);
        assert_eq!(fault_snapshot(&connection), before);
        drop(connection);
        assert!(
            open(&root)
                .consume_fault(fixture::facts([1, 2, 3, 4]), binding(5, 6))
                .is_err()
        );
    }
}

#[test]
fn migration_crash_child() {
    let Ok(root) = std::env::var("RUNNE_TEST_LEDGER_MIGRATION_ROOT") else {
        return;
    };
    let _ = QualificationReplayLedger::open_for_test(std::path::Path::new(&root), uid());
    panic!("migration must abort at its exact boundary");
}
