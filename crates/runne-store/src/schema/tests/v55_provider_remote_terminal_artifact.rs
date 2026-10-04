#[test]
fn v55_adds_encrypted_remote_terminal_fact_and_preserves_v50_rows() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 54).unwrap();
    assert!(v54_matches(&connection, 54).unwrap());
    apply_migrations_internal(&connection, 55).unwrap();

    assert_eq!(schema_marker(&connection), 55);
    assert!(v42_structure_matches(&connection, true).unwrap(), "catalog");
    assert!(v48_matches(&connection, 55).unwrap(), "v48 inherited");
    assert!(v47_matches(&connection, 55).unwrap(), "v47 inherited");
    assert!(v46_matches(&connection, 55).unwrap(), "v46 inherited");
    assert!(v45_matches(&connection, 55).unwrap(), "v45 inherited");
    assert!(v44_matches(&connection, 55).unwrap(), "v44 inherited");
    assert!(v43_matches(&connection, 55).unwrap(), "v43 inherited");
    assert!(v49_matches(&connection, 55).unwrap(), "v49 inherited");
    assert!(
        v55_disposition_objects_match(&connection).unwrap(),
        "dispositions early"
    );
    assert!(v50_base_matches(&connection, 55).unwrap(), "v50 inherited");
    assert!(v51_base_matches(&connection, 55).unwrap(), "v51 inherited");
    assert!(v52_base_matches(&connection, 55).unwrap(), "v52 inherited");
    assert!(v53_base_matches(&connection, 55).unwrap(), "v53 inherited");
    assert!(v54_matches(&connection, 55).unwrap(), "v54 inherited");
    assert!(
        v55_disposition_objects_match(&connection).unwrap(),
        "dispositions"
    );
    assert!(
        table_sql_matches_migration(
            &connection,
            "provider_remote_terminal_artifacts",
            MIGRATION_V55
        )
        .unwrap(),
        "artifact ddl"
    );
    assert!(v55_matches(&connection, 55).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
    let ddl: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_remote_terminal_artifacts'",
        [], |row| row.get(0),
    ).unwrap();
    assert!(ddl.contains("disposition IN (1,2,3,5)"));

    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection.execute(
        "INSERT INTO provider_terminal_dispositions(dispatch_attempt_id,disposition) VALUES(?1,5)",
        [[1_u8; 16]],
    ).unwrap();
    assert!(connection.execute(
        "INSERT INTO provider_terminal_dispositions(dispatch_attempt_id,disposition) VALUES(?1,7)",
        [[2_u8; 16]],
    ).is_err());
}

#[test]
fn v55_rejects_missing_artifact_guards_and_keeps_historical_v54_valid() {
    for trigger in [
        "provider_remote_terminal_artifacts_immutable",
        "provider_remote_terminal_artifacts_no_delete",
        "schema_v12_fence_provider_remote_terminal_artifacts_insert",
        "schema_v12_fence_provider_remote_terminal_artifacts_update",
        "schema_v12_fence_provider_remote_terminal_artifacts_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 55).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v55_matches(&connection, 55).unwrap(), "{trigger}");
        assert!(
            classify_existing_connection(&connection).is_err(),
            "{trigger}"
        );
    }
    let historical = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&historical, 54).unwrap();
    assert!(v54_matches(&historical, 54).unwrap());
}

#[test]
fn v55_migration_copies_all_preexisting_v50_disposition_codes() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 54).unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    for code in 1..=4_i64 {
        connection.execute(
            "INSERT INTO provider_terminal_dispositions(dispatch_attempt_id,disposition) VALUES(?1,?2)",
            rusqlite::params![[code as u8; 16], code],
        ).unwrap();
    }
    apply_v55_migration(&connection).unwrap();
    let copied: Vec<i64> = {
        let mut statement = connection
            .prepare("SELECT disposition FROM provider_terminal_dispositions ORDER BY disposition")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(copied, [1, 2, 3, 4]);
}

#[test]
fn v55_audit_only_requires_the_exact_accepted_cancel_receipt() {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::task_run::TaskRunEvent;

    let codec = TaskRunEventCodec;
    let accepted = codec.encode(&TaskRunEvent::CancellationRequested).unwrap();
    let completed = codec.encode(&TaskRunEvent::CancellationCompleted).unwrap();
    let cancelled = codec.encode(&TaskRunEvent::TaskRunCancelled).unwrap();
    assert!(v55_is_cancel_request_payload(&accepted));
    assert!(!v55_is_cancel_request_payload(&completed));
    assert!(!v55_is_cancel_request_payload(&cancelled));
    assert!(!v55_is_cancel_request_payload(b"not-a-taskrun-event"));

    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 55).unwrap();
    // V55 predates the exact attempt-scoped cancel receipt; code 6 stays fail-closed.
    assert!(!v55_audit_only_cancel_fence_matches(&connection, &[0x55; 16]).unwrap());
}
use crate::codec::{StoreCodec, TaskRunEventCodec};
use runne_domain::task_run::TaskRunEvent;

fn v55_is_cancel_request_payload(bytes: &[u8]) -> bool {
    matches!(
        StoreCodec::decode(&TaskRunEventCodec, bytes),
        Ok(TaskRunEvent::CancellationRequested)
    )
}
