pub(super) const MIGRATION_V35: &str = r#"
DROP INDEX provider_credential_one_non_terminal_operation;
CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action NOT IN ('LEGACY_SOURCE_CLEANUP', 'RETIRED_VERSION_CLEANUP');
CREATE UNIQUE INDEX provider_credential_one_pending_retired_version_cleanup
    ON provider_credential_operations(provider_id)
    WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')
      AND action = 'RETIRED_VERSION_CLEANUP';
"#;

pub(super) fn apply_v35_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V35)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (35)", [])?;
    transaction.commit()
}
