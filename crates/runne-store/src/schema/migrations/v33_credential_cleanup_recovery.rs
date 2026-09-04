pub(super) const MIGRATION_V33: &str = r#"
CREATE TABLE credential_cleanup_recovery_attempts (
    operation_id BLOB NOT NULL REFERENCES provider_credential_operations(operation_id),
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    installation_owner_id BLOB NOT NULL CHECK(length(installation_owner_id) = 32 AND installation_owner_id != zeroblob(32)),
    release_tuple_digest BLOB NOT NULL CHECK(length(release_tuple_digest) = 32 AND release_tuple_digest != zeroblob(32)),
    protected_session_digest BLOB NOT NULL CHECK(length(protected_session_digest) = 32 AND protected_session_digest != zeroblob(32)),
    database_generation INTEGER NOT NULL CHECK(database_generation > 0),
    supervisor_generation INTEGER NOT NULL CHECK(supervisor_generation > 0),
    lifecycle_revision INTEGER NOT NULL CHECK(lifecycle_revision > 0),
    credential_fence INTEGER NOT NULL CHECK(credential_fence > 0),
    continuation_digest BLOB NOT NULL UNIQUE CHECK(length(continuation_digest) = 32 AND continuation_digest != zeroblob(32)),
    issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    state TEXT NOT NULL CHECK(state IN ('ACCEPTED', 'CONSUMED', 'SUPERSEDED')),
    terminal_digest BLOB CHECK(terminal_digest IS NULL OR length(terminal_digest) = 32),
    PRIMARY KEY(operation_id, attempt),
    CHECK((state = 'ACCEPTED' AND terminal_digest IS NULL) OR (state != 'ACCEPTED' AND terminal_digest IS NOT NULL AND terminal_digest = continuation_digest))
) STRICT;
CREATE UNIQUE INDEX credential_cleanup_recovery_one_live
    ON credential_cleanup_recovery_attempts(operation_id) WHERE state = 'ACCEPTED';
CREATE TRIGGER credential_cleanup_recovery_insert BEFORE INSERT ON credential_cleanup_recovery_attempts
WHEN NEW.state != 'ACCEPTED' OR NEW.terminal_digest IS NOT NULL
 OR NEW.attempt != COALESCE((SELECT MAX(attempt) + 1 FROM credential_cleanup_recovery_attempts WHERE operation_id = NEW.operation_id), 1)
 OR NOT EXISTS (
    SELECT 1 FROM provider_credential_operations AS o
    JOIN provider_credential_authority_heads AS h ON h.provider_id = o.provider_id
    WHERE o.operation_id = NEW.operation_id AND o.state = 'PREPARED'
      AND o.action IN ('REVOKE', 'RETIRED_VERSION_CLEANUP', 'LEGACY_SOURCE_CLEANUP')
      AND o.installation_owner_id = NEW.installation_owner_id
      AND o.qualified_release_tuple_digest = NEW.release_tuple_digest
      AND (o.action != 'LEGACY_SOURCE_CLEANUP' OR
           (h.legacy_import_consumed = 1 AND h.legacy_source_binding_digest IS NOT NULL
            AND h.legacy_cleanup_operation_id = o.operation_id))
      AND h.lifecycle_revision = NEW.lifecycle_revision AND h.credential_fence = NEW.credential_fence
      AND ((o.action = 'REVOKE' AND o.expected_lifecycle_revision + 1 = h.lifecycle_revision AND o.expected_credential_fence + 1 = h.credential_fence)
        OR (o.action != 'REVOKE' AND o.expected_lifecycle_revision = h.lifecycle_revision AND o.expected_credential_fence = h.credential_fence))
      AND h.hard_fence_disposition IS NULL AND h.release_migration_state IN ('NONE', 'CLEARED')
      AND NEW.issued_at >= h.observed_at_high_water)
 OR EXISTS (SELECT 1 FROM provider_credential_ticket_attempts WHERE operation_id = NEW.operation_id AND state IN ('ISSUED', 'CLAIMED'))
 OR EXISTS (SELECT 1 FROM provider_credential_process_attachments WHERE operation_id = NEW.operation_id AND state = 'ATTACHED')
BEGIN SELECT RAISE(ABORT, 'credential cleanup recovery is not fenced and current'); END;
CREATE TRIGGER credential_cleanup_recovery_immutable BEFORE UPDATE ON credential_cleanup_recovery_attempts
WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.attempt IS NOT OLD.attempt
 OR NEW.installation_owner_id IS NOT OLD.installation_owner_id OR NEW.release_tuple_digest IS NOT OLD.release_tuple_digest
 OR NEW.protected_session_digest IS NOT OLD.protected_session_digest
 OR NEW.database_generation IS NOT OLD.database_generation OR NEW.supervisor_generation IS NOT OLD.supervisor_generation
 OR NEW.lifecycle_revision IS NOT OLD.lifecycle_revision OR NEW.credential_fence IS NOT OLD.credential_fence
 OR NEW.continuation_digest IS NOT OLD.continuation_digest
 OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
 OR NOT (OLD.state = 'ACCEPTED' AND NEW.state IN ('CONSUMED', 'SUPERSEDED') AND NEW.terminal_digest IS OLD.continuation_digest)
BEGIN SELECT RAISE(ABORT, 'credential cleanup recovery binding is immutable'); END;
CREATE TRIGGER credential_cleanup_recovery_no_delete BEFORE DELETE ON credential_cleanup_recovery_attempts
BEGIN SELECT RAISE(ABORT, 'credential cleanup recovery is append only'); END;
"#;

pub(super) fn apply_v33_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V33)?;
    transaction.execute_batch("DROP TRIGGER provider_credential_attachment_insert; DROP TRIGGER provider_credential_ticket_insert_issued;")?;
    transaction.execute_batch(&v33_attachment_trigger())?;
    transaction.execute_batch(&v33_ticket_trigger())?;
    install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (33)", [])?;
    transaction.commit()
}
