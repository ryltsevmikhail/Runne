pub(super) const MIGRATION_V62: &str = r#"
CREATE TABLE provider_remote_terminal_audit_receipts (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 response_id_digest BLOB NOT NULL CHECK(length(response_id_digest)=32 AND response_id_digest!=zeroblob(32)),
 artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32 AND artifact_digest!=zeroblob(32)),
 terminal_status INTEGER NOT NULL CHECK(terminal_status IN (1,2,3,5)),
 witness_kind INTEGER NOT NULL CHECK(witness_kind IN (1,2)),
 terminal_event_id BLOB CHECK(terminal_event_id IS NULL OR (length(terminal_event_id)=16 AND terminal_event_id!=zeroblob(16))),
 terminal_version INTEGER CHECK(terminal_version IS NULL OR terminal_version>0),
 successor_taskrun_id BLOB CHECK(successor_taskrun_id IS NULL OR (length(successor_taskrun_id)=16 AND successor_taskrun_id!=zeroblob(16))),
 successor_submit_event_id BLOB CHECK(successor_submit_event_id IS NULL OR (length(successor_submit_event_id)=16 AND successor_submit_event_id!=zeroblob(16))),
 successor_submit_version INTEGER CHECK(successor_submit_version IS NULL OR successor_submit_version>0),
 supersession_event_id BLOB CHECK(supersession_event_id IS NULL OR (length(supersession_event_id)=16 AND supersession_event_id!=zeroblob(16))),
 supersession_version INTEGER CHECK(supersession_version IS NULL OR supersession_version>0),
 release_event_id BLOB NOT NULL CHECK(length(release_event_id)=16 AND release_event_id!=zeroblob(16)),
 release_version INTEGER NOT NULL CHECK(release_version>0),
 release_fence INTEGER NOT NULL CHECK(release_fence>0),
 release_reason TEXT NOT NULL CHECK(release_reason IN ('terminal_settlement','user_supersession')),
 acknowledgement_digest BLOB CHECK(acknowledgement_digest IS NULL OR (length(acknowledgement_digest)=32 AND acknowledgement_digest!=zeroblob(32))),
 conversation_observed_event_id BLOB NOT NULL CHECK(length(conversation_observed_event_id)=16 AND conversation_observed_event_id!=zeroblob(16)),
 conversation_observed_version INTEGER NOT NULL CHECK(conversation_observed_version>0),
 accounting_state INTEGER NOT NULL CHECK(accounting_state IN (1,2)),
 accounting_digest BLOB CHECK(accounting_digest IS NULL OR (length(accounting_digest)=32 AND accounting_digest!=zeroblob(32))),
 audit_digest BLOB NOT NULL CHECK(length(audit_digest)=32 AND audit_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((terminal_event_id IS NULL)=(terminal_version IS NULL)),
 CHECK((successor_taskrun_id IS NULL)=(successor_submit_event_id IS NULL)
   AND (successor_taskrun_id IS NULL)=(successor_submit_version IS NULL)),
 CHECK((supersession_event_id IS NULL)=(supersession_version IS NULL)),
 CHECK((witness_kind=1 AND terminal_event_id IS NOT NULL AND successor_taskrun_id IS NULL
   AND supersession_event_id IS NULL AND release_reason='terminal_settlement'
   AND release_event_id=terminal_event_id AND release_version=terminal_version
   AND acknowledgement_digest IS NULL)
   OR (witness_kind=2 AND terminal_event_id IS NULL AND successor_taskrun_id IS NOT NULL
   AND supersession_event_id IS NOT NULL AND release_reason='user_supersession'
   AND release_event_id=supersession_event_id AND release_version=supersession_version
   AND acknowledgement_digest IS NOT NULL)),
 CHECK((accounting_state=1 AND accounting_digest IS NOT NULL)
   OR (accounting_state=2 AND accounting_digest IS NULL)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_settlements(dispatch_attempt_id),
 FOREIGN KEY(terminal_event_id) REFERENCES events(event_id),
 FOREIGN KEY(successor_submit_event_id) REFERENCES events(event_id),
 FOREIGN KEY(supersession_event_id) REFERENCES events(event_id),
 FOREIGN KEY(release_event_id) REFERENCES events(event_id),
 FOREIGN KEY(conversation_observed_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER provider_remote_terminal_audit_receipts_immutable BEFORE UPDATE ON provider_remote_terminal_audit_receipts BEGIN SELECT RAISE(ABORT,'remote terminal audit receipt is append only'); END;
CREATE TRIGGER provider_remote_terminal_audit_receipts_no_delete BEFORE DELETE ON provider_remote_terminal_audit_receipts BEGIN SELECT RAISE(ABORT,'remote terminal audit receipt is append only'); END;
"#;

pub(super) fn apply_v62_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V62)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(
            &v12_fence_trigger("provider_remote_terminal_audit_receipts", operation).1,
        )?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(62)", [])?;
    tx.commit()
}

pub(super) fn v62_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 62
        || !v61_matches(connection, version)?
        || !table_sql_matches_migration(
            connection,
            "provider_remote_terminal_audit_receipts",
            MIGRATION_V62,
        )?
    {
        return Ok(false);
    }
    for (name, expected) in V62_RECEIPT_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) =
            v12_fence_trigger("provider_remote_terminal_audit_receipts", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    v62_audit_receipts_match(connection)
}

pub(super) fn v62_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_terminal_audit_receipts");
    triggers.extend_from_slice(V62_RECEIPT_TRIGGERS);
    triggers.extend_from_slice(V62_FENCE_TRIGGERS);
}

const V62_RECEIPT_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_remote_terminal_audit_receipts_immutable",
        "CREATE TRIGGER provider_remote_terminal_audit_receipts_immutable BEFORE UPDATE ON provider_remote_terminal_audit_receipts BEGIN SELECT RAISE(ABORT,'remote terminal audit receipt is append only'); END",
    ),
    (
        "provider_remote_terminal_audit_receipts_no_delete",
        "CREATE TRIGGER provider_remote_terminal_audit_receipts_no_delete BEFORE DELETE ON provider_remote_terminal_audit_receipts BEGIN SELECT RAISE(ABORT,'remote terminal audit receipt is append only'); END",
    ),
];

const V62_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_terminal_audit_receipts_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_audit_receipts_insert\" AFTER INSERT ON \"provider_remote_terminal_audit_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_audit_receipts_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_audit_receipts_update\" AFTER UPDATE ON \"provider_remote_terminal_audit_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_audit_receipts_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_audit_receipts_delete\" AFTER DELETE ON \"provider_remote_terminal_audit_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V62AuditDigestFields {
    pub(crate) dispatch: [u8; 16],
    pub(crate) taskrun: [u8; 16],
    pub(crate) attempt: [u8; 16],
    pub(crate) conversation: [u8; 16],
    pub(crate) request: [u8; 32],
    pub(crate) response: [u8; 32],
    pub(crate) artifact: [u8; 32],
    pub(crate) terminal_status: i64,
    pub(crate) witness_kind: i64,
    pub(crate) terminal_event: Option<[u8; 16]>,
    pub(crate) terminal_version: Option<i64>,
    pub(crate) successor_taskrun: Option<[u8; 16]>,
    pub(crate) successor_submit_event: Option<[u8; 16]>,
    pub(crate) successor_submit_version: Option<i64>,
    pub(crate) supersession_event: Option<[u8; 16]>,
    pub(crate) supersession_version: Option<i64>,
    pub(crate) release_event: [u8; 16],
    pub(crate) release_version: i64,
    pub(crate) release_fence: i64,
    pub(crate) release_reason: String,
    pub(crate) acknowledgement: Option<[u8; 32]>,
    pub(crate) conversation_observed_event: [u8; 16],
    pub(crate) conversation_observed_version: i64,
    pub(crate) accounting_state: i64,
    pub(crate) accounting_digest: Option<[u8; 32]>,
}

pub(crate) fn v62_audit_digest(fields: &V62AuditDigestFields) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"gocode/provider/remote-terminal-audit/v1\0");
    hash.update(fields.dispatch);
    hash.update(fields.taskrun);
    hash.update(fields.attempt);
    hash.update(fields.conversation);
    hash.update(fields.request);
    hash.update(fields.response);
    hash.update(fields.artifact);
    hash.update(fields.terminal_status.to_be_bytes());
    hash.update(fields.witness_kind.to_be_bytes());
    for value in [
        fields.terminal_event,
        fields.successor_taskrun,
        fields.successor_submit_event,
        fields.supersession_event,
    ] {
        hash_optional(&mut hash, value.as_ref().map(|bytes| bytes.as_slice()));
    }
    for value in [
        fields.terminal_version,
        fields.successor_submit_version,
        fields.supersession_version,
    ] {
        match value {
            Some(number) => {
                hash.update([1]);
                hash.update(number.to_be_bytes());
            }
            None => hash.update([0]),
        }
    }
    hash.update(fields.release_event);
    hash.update(fields.release_version.to_be_bytes());
    hash.update(fields.release_fence.to_be_bytes());
    hash.update((fields.release_reason.len() as u64).to_be_bytes());
    hash.update(fields.release_reason.as_bytes());
    hash_optional(
        &mut hash,
        fields
            .acknowledgement
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    );
    hash.update(fields.conversation_observed_event);
    hash.update(fields.conversation_observed_version.to_be_bytes());
    hash.update(fields.accounting_state.to_be_bytes());
    hash_optional(
        &mut hash,
        fields
            .accounting_digest
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    );
    hash.finalize().into()
}

fn hash_optional(hash: &mut impl sha2::Digest, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            hash.update([1]);
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        None => hash.update([0]),
    }
}

include!("v62_remote_terminal_audit_match.rs");
