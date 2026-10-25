pub(super) const MIGRATION_V60: &str = r#"
CREATE TABLE provider_remote_artifact_cancel_closures (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32 AND artifact_digest!=zeroblob(32)),
 terminal_status INTEGER NOT NULL CHECK(terminal_status IN (1,2,3,5)),
 cancellation_command_id BLOB NOT NULL CHECK(length(cancellation_command_id)=16 AND cancellation_command_id!=zeroblob(16)),
 cancellation_event_id BLOB NOT NULL CHECK(length(cancellation_event_id)=16 AND cancellation_event_id!=zeroblob(16)),
 cancellation_taskrun_version INTEGER NOT NULL CHECK(cancellation_taskrun_version>0),
 taskrun_terminal_event_id BLOB NOT NULL CHECK(length(taskrun_terminal_event_id)=16 AND taskrun_terminal_event_id!=zeroblob(16)),
 taskrun_terminal_version INTEGER NOT NULL CHECK(taskrun_terminal_version>cancellation_taskrun_version),
 observed_conversation_head_event_id BLOB NOT NULL CHECK(length(observed_conversation_head_event_id)=16 AND observed_conversation_head_event_id!=zeroblob(16)),
 observed_conversation_head_version INTEGER NOT NULL CHECK(observed_conversation_head_version>0),
 conversation_terminal_event_id BLOB CHECK(conversation_terminal_event_id IS NULL OR (length(conversation_terminal_event_id)=16 AND conversation_terminal_event_id!=zeroblob(16))),
 conversation_terminal_version INTEGER CHECK(conversation_terminal_version IS NULL OR conversation_terminal_version>observed_conversation_head_version),
 closure_digest BLOB NOT NULL CHECK(length(closure_digest)=32 AND closure_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((conversation_terminal_event_id IS NULL)=(conversation_terminal_version IS NULL)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_settlements(dispatch_attempt_id),
 FOREIGN KEY(cancellation_command_id) REFERENCES command_receipts(command_id),
 FOREIGN KEY(cancellation_event_id) REFERENCES events(event_id),
 FOREIGN KEY(taskrun_terminal_event_id) REFERENCES events(event_id),
 FOREIGN KEY(observed_conversation_head_event_id) REFERENCES events(event_id),
 FOREIGN KEY(conversation_terminal_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER provider_remote_artifact_cancel_closures_immutable BEFORE UPDATE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END;
CREATE TRIGGER provider_remote_artifact_cancel_closures_no_delete BEFORE DELETE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END;
"#;

pub(super) fn apply_v60_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V60)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(
            &v12_fence_trigger("provider_remote_artifact_cancel_closures", operation).1,
        )?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(60)", [])?;
    tx.commit()
}

pub(super) fn v60_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 60..=69)
        || !v59_matches(connection, version)?
        || !table_sql_matches_migration(
            connection,
            "provider_remote_artifact_cancel_closures",
            MIGRATION_V60,
        )?
    {
        return Ok(false);
    }
    for (name, expected) in [
        (
            "provider_remote_artifact_cancel_closures_immutable",
            "CREATE TRIGGER provider_remote_artifact_cancel_closures_immutable BEFORE UPDATE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END",
        ),
        (
            "provider_remote_artifact_cancel_closures_no_delete",
            "CREATE TRIGGER provider_remote_artifact_cancel_closures_no_delete BEFORE DELETE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END",
        ),
    ] {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) =
            v12_fence_trigger("provider_remote_artifact_cancel_closures", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    v60_rows_match(connection)
}

pub(crate) fn verify_v60_remote_artifact_cancel_closures(
    connection: &Connection,
) -> SqliteResult<bool> {
    v60_rows_match(connection)
}

pub(super) fn v60_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_artifact_cancel_closures");
    triggers.extend([
        ("provider_remote_artifact_cancel_closures_immutable", "CREATE TRIGGER provider_remote_artifact_cancel_closures_immutable BEFORE UPDATE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END"),
        ("provider_remote_artifact_cancel_closures_no_delete", "CREATE TRIGGER provider_remote_artifact_cancel_closures_no_delete BEFORE DELETE ON provider_remote_artifact_cancel_closures BEGIN SELECT RAISE(ABORT,'remote artifact cancel closure is append only'); END"),
    ]);
    triggers.extend_from_slice(V60_FENCE_TRIGGERS);
}

const V60_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_artifact_cancel_closures_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_artifact_cancel_closures_insert\" AFTER INSERT ON \"provider_remote_artifact_cancel_closures\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_artifact_cancel_closures_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_artifact_cancel_closures_update\" AFTER UPDATE ON \"provider_remote_artifact_cancel_closures\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_artifact_cancel_closures_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_artifact_cancel_closures_delete\" AFTER DELETE ON \"provider_remote_artifact_cancel_closures\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

fn v60_hex_authority(authority_id: &[u8; 16]) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in authority_id {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

include!("v60_remote_artifact_cancel_closure_match.rs");
include!("v60_remote_artifact_cancel_closure_evidence.rs");
