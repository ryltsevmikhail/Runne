pub(super) const MIGRATION_V31: &str = r#"
DROP TRIGGER provider_credential_operation_insert_prepared;
"#;

pub(super) fn apply_v31_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V31)?;
    transaction.execute_batch(&v31_trigger())?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (31)", [])?;
    transaction.commit()
}
