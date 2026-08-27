pub(super) const MIGRATION_V27: &str = r#"
ALTER TABLE provider_credential_operations ADD COLUMN broker_migration_binding_digest BLOB CHECK(broker_migration_binding_digest IS NULL OR length(broker_migration_binding_digest) = 32);
ALTER TABLE provider_credential_operations ADD COLUMN claimed_ticket_attempt INTEGER CHECK(claimed_ticket_attempt IS NULL OR claimed_ticket_attempt > 0);
CREATE TRIGGER provider_credential_migration_provenance_insert BEFORE INSERT ON provider_credential_operations WHEN (NEW.action IN ('WRITER_IDENTITY_MIGRATION_EFFECT', 'WRITER_IDENTITY_MIGRATION_VERIFY') AND (NEW.broker_migration_binding_digest IS NULL OR length(NEW.broker_migration_binding_digest) != 32 OR NEW.broker_migration_binding_digest = zeroblob(32))) OR (NEW.action NOT IN ('WRITER_IDENTITY_MIGRATION_EFFECT', 'WRITER_IDENTITY_MIGRATION_VERIFY') AND NEW.broker_migration_binding_digest IS NOT NULL) OR NEW.claimed_ticket_attempt IS NOT NULL BEGIN SELECT RAISE(ABORT, 'credential migration provenance is missing, fabricated, or premature'); END;
CREATE TRIGGER provider_credential_migration_provenance_immutable BEFORE UPDATE ON provider_credential_operations WHEN NEW.broker_migration_binding_digest IS NOT OLD.broker_migration_binding_digest BEGIN SELECT RAISE(ABORT, 'credential migration provenance is immutable'); END;
CREATE TRIGGER provider_credential_claimed_attempt_transition BEFORE UPDATE ON provider_credential_operations WHEN NEW.claimed_ticket_attempt IS NOT OLD.claimed_ticket_attempt AND NOT (OLD.claimed_ticket_attempt IS NULL AND OLD.state = 'PREPARED' AND NEW.state = 'CLAIMED' AND NEW.claimed_ticket_attempt > 0) BEGIN SELECT RAISE(ABORT, 'credential claimed ticket attempt is immutable'); END;
"#;

pub(super) fn apply_v27_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V27)?;
    install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (27)", [])?;
    transaction.commit()
}
