pub(super) const MIGRATION_V35: &str = r#"
CREATE TABLE provider_qualification_admission_fences (
    operation_id BLOB NOT NULL CHECK(length(operation_id)=16 AND operation_id!=zeroblob(16)),
    attempt INTEGER NOT NULL CHECK(attempt>0),
    context_id BLOB NOT NULL UNIQUE CHECK(length(context_id)=32 AND context_id!=zeroblob(32)),
    context_nonce BLOB NOT NULL UNIQUE CHECK(length(context_nonce)=32 AND context_nonce!=zeroblob(32)),
    ticket_id BLOB NOT NULL UNIQUE CHECK(length(ticket_id)=32 AND ticket_id!=zeroblob(32)),
    ticket_nonce BLOB NOT NULL UNIQUE CHECK(length(ticket_nonce)=32 AND ticket_nonce!=zeroblob(32)),
    ticket_sha256 BLOB NOT NULL CHECK(length(ticket_sha256)=32 AND ticket_sha256!=zeroblob(32)),
    scenario_id TEXT NOT NULL CHECK(scenario_id='macos-xpc-dpk-v1'),
    selector TEXT NOT NULL CHECK(selector IN ('kill_before_service_consume','kill_after_service_consume','kill_before_native_effect','kill_after_native_effect','kill_before_readback','kill_after_readback','kill_before_reply','kill_after_reply','kill_before_lifecycle_cas','kill_after_lifecycle_cas','kill_desktop_process','kill_writer_process','kill_runtime_process','kill_service_launchd_restart','kill_registration_ack_loss')),
    process_role TEXT NOT NULL CHECK(process_role IN ('desktop','writer','runtime','service')),
    candidate_sha256 BLOB NOT NULL CHECK(length(candidate_sha256)=32 AND candidate_sha256!=zeroblob(32)),
    raw_v3_tuple_sha256 BLOB NOT NULL CHECK(length(raw_v3_tuple_sha256)=32 AND raw_v3_tuple_sha256!=zeroblob(32)),
    source_revision BLOB NOT NULL CHECK(length(source_revision)=20 AND source_revision!=zeroblob(20)),
    workflow_run_id TEXT NOT NULL CHECK(typeof(workflow_run_id)='text' AND length(CAST(workflow_run_id AS BLOB)) BETWEEN 1 AND 128 AND length(CAST(workflow_run_id AS BLOB))=length(workflow_run_id) AND workflow_run_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    namespace_sha256 BLOB NOT NULL CHECK(length(namespace_sha256)=32 AND namespace_sha256!=zeroblob(32)),
    context_issued_at INTEGER NOT NULL CHECK(context_issued_at>=0),
    context_expires_at INTEGER NOT NULL CHECK(context_expires_at>context_issued_at AND context_expires_at-context_issued_at<=900),
    ticket_issued_at INTEGER NOT NULL CHECK(ticket_issued_at>=0),
    ticket_expires_at INTEGER NOT NULL CHECK(ticket_expires_at>ticket_issued_at AND ticket_expires_at-ticket_issued_at<=900 AND context_expires_at<=ticket_expires_at),
    protected_session_digest BLOB NOT NULL CHECK(length(protected_session_digest)=32 AND protected_session_digest!=zeroblob(32)),
    runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
    database_generation INTEGER NOT NULL CHECK(database_generation>0),
    launch_generation INTEGER NOT NULL CHECK(launch_generation>0),
    supervisor_generation INTEGER NOT NULL CHECK(supervisor_generation>0),
    verified_at INTEGER NOT NULL CHECK(verified_at>=context_issued_at AND verified_at>=ticket_issued_at AND verified_at<context_expires_at AND verified_at<ticket_expires_at),
    committed_at INTEGER NOT NULL CHECK(committed_at>=verified_at AND committed_at<context_expires_at AND committed_at<ticket_expires_at),
    PRIMARY KEY(operation_id,attempt),
    UNIQUE(operation_id),
    FOREIGN KEY(operation_id,attempt) REFERENCES provider_credential_ticket_attempts(operation_id,attempt)
) STRICT;
CREATE TRIGGER provider_qualification_fence_replay_conflict BEFORE INSERT ON provider_qualification_admission_fences
WHEN EXISTS (
    SELECT 1 FROM provider_qualification_admission_fences AS existing
    WHERE existing.operation_id=NEW.operation_id
       OR existing.context_id=NEW.context_id
       OR existing.context_nonce=NEW.context_nonce
       OR existing.ticket_id=NEW.ticket_id
       OR existing.ticket_nonce=NEW.ticket_nonce
)
BEGIN SELECT RAISE(ABORT,'qualification fence replay conflict'); END;
CREATE TRIGGER provider_qualification_fence_insert_guard BEFORE INSERT ON provider_qualification_admission_fences
WHEN NOT EXISTS (
    SELECT 1 FROM provider_credential_ticket_attempts AS ticket
    JOIN provider_credential_process_attachments AS attachment
      ON attachment.operation_id=ticket.operation_id
     AND attachment.continuation_binding_digest=ticket.continuation_binding_digest
    JOIN provider_credential_operations AS operation ON operation.operation_id=ticket.operation_id
    JOIN provider_credential_authority_heads AS head ON head.provider_id=operation.provider_id
    WHERE ticket.operation_id=NEW.operation_id AND ticket.attempt=NEW.attempt
      AND ticket.state='ISSUED' AND attachment.state='ATTACHED'
      AND operation.state='PREPARED' AND operation.action='PAIR'
      AND operation.expected_lifecycle_revision=head.lifecycle_revision
      AND operation.expected_credential_fence=head.credential_fence
      AND head.hard_fence_disposition IS NULL AND head.release_migration_state IN ('NONE','CLEARED')
      AND operation.begin_proof_expires_at_high_water>NEW.committed_at
      AND ticket.issued_at<=NEW.committed_at AND ticket.expires_at>NEW.committed_at
)
BEGIN SELECT RAISE(ABORT,'qualification fence requires the exact live issued attempt'); END;
CREATE TRIGGER provider_qualification_fence_selector_role BEFORE INSERT ON provider_qualification_admission_fences
WHEN NOT ((NEW.process_role='desktop' AND NEW.selector='kill_desktop_process')
 OR (NEW.process_role='writer' AND NEW.selector='kill_writer_process')
 OR (NEW.process_role='runtime' AND NEW.selector IN ('kill_before_lifecycle_cas','kill_after_lifecycle_cas','kill_runtime_process'))
 OR (NEW.process_role='service' AND NEW.selector IN ('kill_before_service_consume','kill_after_service_consume','kill_before_native_effect','kill_after_native_effect','kill_before_readback','kill_after_readback','kill_before_reply','kill_after_reply','kill_service_launchd_restart','kill_registration_ack_loss')))
BEGIN SELECT RAISE(ABORT,'qualification selector role mismatch'); END;
CREATE TRIGGER provider_qualification_fence_no_update BEFORE UPDATE ON provider_qualification_admission_fences
BEGIN SELECT RAISE(ABORT,'qualification fence is append only'); END;
CREATE TRIGGER provider_qualification_fence_no_delete BEFORE DELETE ON provider_qualification_admission_fences
BEGIN SELECT RAISE(ABORT,'qualification fence is permanent'); END;
"#;

pub(super) fn apply_v35_migration(conn: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V35)?;
    install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (35)", [])?;
    transaction.commit()
}
