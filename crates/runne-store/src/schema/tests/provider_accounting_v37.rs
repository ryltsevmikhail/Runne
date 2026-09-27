#[test]
fn v37_upgrade_preserves_legacy_schema_and_allows_only_typed_zero_cost() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v13(&conn);
    apply_migrations(&conn).unwrap();
    assert_eq!(schema_marker(&conn), 47);
    assert!(v46_matches(&conn, 47).unwrap());
    let trigger: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            ["schema_v12_fence_provider_execution_admissions_delete"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(trigger.contains("provider_execution_admissions"));

    conn.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    conn.execute(
        "INSERT INTO provider_budget_reservations
         (reservation_id, provider_idempotency_key, dimension, amount, state)
         VALUES (zeroblob(16), 'legacy-key', 2, 0, 1)",
        [],
    )
    .unwrap();
    assert!(conn
        .execute(
            "INSERT INTO provider_budget_reservations
             (reservation_id, provider_idempotency_key, dimension, amount, state)
             VALUES (randomblob(16), 'paid-key', 1, 0, 1)",
            [],
        )
        .is_err());
}

#[test]
fn v37_rejects_tampered_accounting_constraints() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF;
         CREATE TABLE provider_budget_reservations_copy AS
         SELECT * FROM provider_budget_reservations;
         DROP TABLE provider_budget_reservations;
         ALTER TABLE provider_budget_reservations_copy
         RENAME TO provider_budget_reservations;",
    )
    .unwrap();
    assert!(!v37_matches(&conn, 37).unwrap());
}

#[test]
fn v37_rejects_unexpected_accounting_index() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();
    conn.execute(
        "CREATE INDEX v37_unexpected_admission_index ON provider_execution_admissions(principal_id)",
        [],
    )
    .unwrap();
    assert!(!v37_matches(&conn, 37).unwrap());
}
