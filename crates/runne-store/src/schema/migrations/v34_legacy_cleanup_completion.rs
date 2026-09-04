// Keep the V28/V33 catalog intact for existing database admission.
fn v34_completion_trigger() -> String {
    v28_trigger_source("provider_credential_completion_receipt_insert")
        .replace("NEW.successor_lifecycle_revision != NEW.predecessor_lifecycle_revision OR NEW.successor_credential_fence != NEW.predecessor_credential_fence",
                 "NEW.successor_lifecycle_revision < NEW.predecessor_lifecycle_revision OR NEW.successor_credential_fence < NEW.predecessor_credential_fence")
        .replace("NEW.readiness_observation_id IS NOT NULL OR",
                 "NEW.readiness_observation_id IS NOT NULL OR NOT EXISTS (SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id=NEW.provider_id AND h.hard_fence_disposition IS NULL AND h.legacy_import_consumed=1 AND h.legacy_cleanup_operation_id=NEW.operation_id AND h.legacy_consumed_lifecycle_revision=NEW.predecessor_lifecycle_revision) OR")
}

pub(super) fn v34_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    v33_family_matches(connection, version, true)
}

fn v34_attachment_trigger() -> String {
    v33_attachment_trigger().replace(
        "operation.action != 'REVOKE' AND operation.expected_lifecycle_revision = head.lifecycle_revision AND operation.expected_credential_fence = head.credential_fence",
        "(operation.action NOT IN ('REVOKE', 'LEGACY_SOURCE_CLEANUP') AND operation.expected_lifecycle_revision = head.lifecycle_revision AND operation.expected_credential_fence = head.credential_fence) OR (operation.action = 'LEGACY_SOURCE_CLEANUP' AND operation.expected_lifecycle_revision <= head.lifecycle_revision AND operation.expected_credential_fence <= head.credential_fence AND head.legacy_import_consumed=1 AND head.legacy_cleanup_operation_id=operation.operation_id AND head.legacy_consumed_lifecycle_revision=operation.expected_lifecycle_revision AND head.legacy_source_binding_digest IS NOT NULL)",
    )
}

fn v34_recovery_trigger() -> String {
    v33_trigger_source("credential_cleanup_recovery_insert").replace(
        "o.action != 'REVOKE' AND o.expected_lifecycle_revision = h.lifecycle_revision AND o.expected_credential_fence = h.credential_fence",
        "(o.action NOT IN ('REVOKE', 'LEGACY_SOURCE_CLEANUP') AND o.expected_lifecycle_revision = h.lifecycle_revision AND o.expected_credential_fence = h.credential_fence) OR (o.action = 'LEGACY_SOURCE_CLEANUP' AND o.expected_lifecycle_revision <= h.lifecycle_revision AND o.expected_credential_fence <= h.credential_fence AND h.legacy_consumed_lifecycle_revision=o.expected_lifecycle_revision)",
    )
}

pub(super) fn apply_v34_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch("DROP TRIGGER provider_credential_completion_receipt_insert;")?;
    transaction.execute_batch(&v34_completion_trigger())?;
    transaction.execute_batch("DROP TRIGGER provider_credential_attachment_insert;")?;
    transaction.execute_batch(&v34_attachment_trigger())?;
    transaction.execute_batch("DROP TRIGGER credential_cleanup_recovery_insert;")?;
    transaction.execute_batch(&v34_recovery_trigger())?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (34)", [])?;
    transaction.commit()
}
