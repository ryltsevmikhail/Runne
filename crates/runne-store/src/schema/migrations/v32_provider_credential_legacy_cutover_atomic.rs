pub(super) const MIGRATION_V32: &str = r#"
DROP INDEX provider_credential_one_non_terminal_operation;
CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action != 'LEGACY_SOURCE_CLEANUP';
CREATE UNIQUE INDEX provider_credential_one_pending_legacy_source_cleanup
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action = 'LEGACY_SOURCE_CLEANUP';
DROP TRIGGER provider_credential_head_active_lifecycle;
DROP TRIGGER provider_credential_operation_insert_prepared;
"#;

pub(super) fn apply_v32_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V32)?;
    transaction.execute_batch(&v32_insert_trigger())?;
    transaction.execute_batch(&v32_head_active_lifecycle_trigger())?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (32)", [])?;
    transaction.commit()
}
