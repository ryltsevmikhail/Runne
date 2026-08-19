#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_initial_migration_does_not_advance_namespaced_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE session_bindings (unexpected INTEGER);")
            .unwrap();
        assert!(apply_migrations_and_verify(&mut conn).is_err());
        let metadata: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'runne_session_binding_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(metadata, 0);
    }

    #[test]
    fn exact_schema_rejects_a_reordered_recovery_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch(
            "DROP INDEX idx_session_bindings_recovery;
             CREATE INDEX idx_session_bindings_recovery
             ON session_bindings(status, runtime_authority_id, created_at, session_id, profile_id, profile_revision);",
        )
        .unwrap();
        assert!(verify_database(&conn).is_err());
    }

    #[test]
    fn exact_schema_rejects_changed_quoted_check_literal() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch("PRAGMA writable_schema = ON;").unwrap();
        conn.execute(
            "UPDATE sqlite_master
             SET sql = replace(sql, ?1, ?2)
             WHERE type = 'table' AND name = 'session_bindings'",
            ["'pending'", "'PENDING'"],
        )
        .unwrap();
        conn.execute_batch("PRAGMA writable_schema = OFF;").unwrap();

        assert!(verify_database(&conn).is_err());
    }

    #[test]
    fn exact_schema_rejects_damaged_namespaced_metadata_ddl() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch("PRAGMA writable_schema = ON;").unwrap();
        conn.execute(
            "UPDATE sqlite_master
             SET sql = replace(sql, ?1, ?2)
             WHERE type = 'table'
               AND name = 'runne_session_binding_schema_version'",
            ["version INTEGER PRIMARY KEY", "version INTEGER"],
        )
        .unwrap();
        conn.execute_batch("PRAGMA writable_schema = OFF;").unwrap();

        assert!(verify_database(&conn).is_err());
    }
}
