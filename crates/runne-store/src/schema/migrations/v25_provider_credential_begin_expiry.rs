pub(super) const MIGRATION_V25: &str = r#"
ALTER TABLE provider_credential_operations ADD COLUMN begin_proof_expires_at_high_water INTEGER NOT NULL DEFAULT 0 CHECK(begin_proof_expires_at_high_water >= 0);
DROP TRIGGER provider_credential_operation_insert_prepared;
DROP TRIGGER provider_credential_operation_transition;
DROP TRIGGER provider_credential_ticket_insert_issued;
"#;

pub(super) fn apply_v25_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V25)?;
    install_v25_successor_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (25)", [])?;
    transaction.commit()
}
