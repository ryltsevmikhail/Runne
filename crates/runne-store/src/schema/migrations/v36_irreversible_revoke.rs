pub(super) const MIGRATION_V36: &str = r#"
CREATE TRIGGER provider_credential_revoke_irreversible
BEFORE UPDATE ON provider_credential_operations
WHEN OLD.action = 'REVOKE'
 AND OLD.state = 'PREPARED'
 AND NEW.state IN ('FAILED', 'EXPIRED', 'CANCELLED')
BEGIN
    SELECT RAISE(ABORT, 'fenced revoke cannot close before reconciliation');
END;
"#;

pub(super) fn apply_v36_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V36)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (36)", [])?;
    transaction.commit()
}
