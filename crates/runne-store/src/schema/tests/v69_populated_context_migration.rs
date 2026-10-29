//! New owned DATA fixtures; no historical native grant, GO or effect evidence.
use super::*;
use crate::store::taskrun_local_command::permission::retained_context_tests::{
    assert_state, with_migration_source,
};
use rusqlite::types::Value;
include!("v69_populated_context_transfer.rs");

#[test]
fn full_history_preserves_populated_capture_and_state_bytes() {
    preserve_populated(true);
}
#[test]
fn missing19_history_preserves_populated_capture_and_state_bytes() {
    preserve_populated(false);
}
fn preserve_populated(full: bool) {
    for state in ["pending", "spent_data", "no_effect_terminal"] {
        with_migration_source(state, |writer, capture_bytes| {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("historical68.sqlite");
            let historical = Connection::open(&path).unwrap();
            historical.execute_batch("PRAGMA foreign_keys=ON").unwrap();
            if full {
                apply_migrations_internal(&historical, 19).unwrap();
            }
            apply_migrations_internal(&historical, 68).unwrap();
            assert!(v68_matches(&historical, 68).unwrap());
            let old_columns = columns(&historical, "x2_permission_bindings");
            assert_eq!(old_columns.len(), 12, "actual old structural catalog");
            assert!(!old_columns.iter().any(|c| c == "retained_context"));
            // Current69 rows supply DATA only; destination is independently built68.
            let mut data = snapshot(writer, &historical);
            // Each fresh DB owns its own immutable v11 snapshot/fence, not donor data.
            data.remove("schema_upgrade_fence");
            transfer(&historical, &data);
            let copied = snapshot_with_columns(&historical, &data);
            for (table, values) in &data {
                assert_eq!(&copied[table], values, "derived old DATA table {table}");
            }
            assert!(
                v68_matches(&historical, 68).unwrap(),
                "populated68 {full}/{state}"
            );
            assert_eq!(
                rows(&historical, "x2_permission_bindings", &old_columns)[0][6],
                Value::Blob(capture_bytes.to_vec()),
                "original CaptureV1 bytes"
            );
            let count: i64 = historical
                .query_row("SELECT COUNT(*) FROM x2_permission_bindings", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(count, 1);
            assert_state(&historical, state);
            let before = snapshot(&historical, &historical);
            let markers_before: Vec<(i64, String)> = historical
                .prepare("SELECT version,applied_at FROM schema_version ORDER BY version")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<SqliteResult<_>>()
                .unwrap();
            assert_eq!(markers_before.len(), if full { 68 } else { 67 });
            assert_eq!(markers_before.iter().any(|(v, _)| *v == 19), full);
            apply_migrations_internal(&historical, 69).unwrap(); // Actual migration-control ->69.
            assert!(v69_matches(&historical, 69).unwrap());
            let old_markers: Vec<(i64, String)> = historical.prepare("SELECT version,applied_at FROM schema_version WHERE version<69 ORDER BY version").unwrap().query_map([], |r| Ok((r.get(0)?,r.get(1)?))).unwrap().collect::<SqliteResult<_>>().unwrap();
            assert_eq!(old_markers, markers_before, "old marker bytes preserved");
            assert_eq!(
                snapshot_with_columns(&historical, &before),
                before,
                "ALL old raw values, source/event rows, digests and state survive"
            );
            let pair: (Option<Vec<u8>>, Option<Vec<u8>>) = historical
                .query_row(
                    "SELECT retained_context,retained_context_digest FROM x2_permission_bindings",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(pair, (None, None), "no backfill");
            assert_state(&historical, state);
            drop(historical);
            let reopened = Connection::open(&path).unwrap();
            reopened.execute_batch("PRAGMA foreign_keys=ON").unwrap();
            assert!(v69_matches(&reopened, 69).unwrap());
            assert!(classify_existing_connection(&reopened).is_ok());
            assert_eq!(snapshot_with_columns(&reopened, &before), before);
            assert_state(&reopened, state);
            let nulls: i64 = reopened.query_row("SELECT COUNT(*) FROM x2_permission_bindings WHERE retained_context IS NULL AND retained_context_digest IS NULL", [], |r| r.get(0)).unwrap();
            assert_eq!(nulls, 1);
            eprintln!(
                "populated68->69 full={full} state={state}: raw old values preserved; NULL pair; reopened ready"
            );
        });
    }
}
