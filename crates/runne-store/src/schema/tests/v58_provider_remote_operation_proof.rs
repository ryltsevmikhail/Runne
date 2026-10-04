#[test]
fn v58_installs_one_use_remote_operation_proof_schema() {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations_internal(&connection, 57).unwrap();
    assert!(v57_matches(&connection, 57).unwrap());
    apply_migrations_internal(&connection, 58).unwrap();
    assert_eq!(schema_marker(&connection), 58);
    assert!(v48_matches(&connection, 58).unwrap(), "v48 chain");
    assert!(v49_matches(&connection, 58).unwrap(), "v49 chain");
    assert!(v50_base_matches(&connection, 58).unwrap(), "v50 chain");
    assert!(v51_base_matches(&connection, 58).unwrap(), "v51 chain");
    assert!(v52_base_matches(&connection, 58).unwrap(), "v52 chain");
    assert!(v53_base_matches(&connection, 58).unwrap(), "v53 chain");
    assert!(v54_matches(&connection, 58).unwrap(), "v54 chain");
    assert!(v55_matches(&connection, 58).unwrap(), "v55 chain");
    assert!(v56_matches(&connection, 58).unwrap(), "v56 chain");
    assert!(v57_matches(&connection, 58).unwrap());
    assert!(v58_matches(&connection, 58).unwrap());
    let ddl: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_remote_operation_proofs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for required in [
        "nonce BLOB PRIMARY KEY",
        "operation INTEGER NOT NULL CHECK(operation IN (1,3))",
        "state INTEGER NOT NULL CHECK(state IN (1,2,3))",
        "response_id_digest BLOB NOT NULL",
        "FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_response_bindings",
    ] {
        assert!(ddl.contains(required), "missing DDL contract: {required}");
    }
}

#[test]
fn v58_readiness_rejects_missing_single_use_guards() {
    for trigger in [
        "provider_remote_operation_proofs_identity_immutable",
        "provider_remote_operation_proofs_state_transition",
        "provider_remote_operation_proofs_no_delete",
        "schema_v12_fence_provider_remote_operation_proofs_insert",
        "schema_v12_fence_provider_remote_operation_proofs_update",
        "schema_v12_fence_provider_remote_operation_proofs_delete",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        apply_migrations_internal(&connection, 58).unwrap();
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger}"))
            .unwrap();
        assert!(!v58_matches(&connection, 58).unwrap(), "{trigger}");
    }
}
