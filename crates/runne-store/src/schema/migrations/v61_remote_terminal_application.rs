pub(super) const MIGRATION_V61: &str = r#"
CREATE TABLE provider_remote_terminal_applications (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 generation_id BLOB NOT NULL CHECK(length(generation_id)=16 AND generation_id!=zeroblob(16)),
 begin_command_id BLOB NOT NULL CHECK(length(begin_command_id)=16 AND begin_command_id!=zeroblob(16)),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 response_id_digest BLOB NOT NULL CHECK(length(response_id_digest)=32 AND response_id_digest!=zeroblob(32)),
 artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32 AND artifact_digest!=zeroblob(32)),
 terminal_status INTEGER NOT NULL CHECK(terminal_status IN (1,2,3,5)),
 publication_disposition INTEGER NOT NULL CHECK(publication_disposition BETWEEN 0 AND 5),
 failure_reason TEXT NOT NULL CHECK(failure_reason IN ('provider_output_rejected','provider_execution_failed','provider_accounting_unknown')),
 accounting_state INTEGER NOT NULL CHECK(accounting_state IN (1,2)),
 accounting_digest BLOB CHECK(accounting_digest IS NULL OR (length(accounting_digest)=32 AND accounting_digest!=zeroblob(32))),
 taskrun_terminal_event_id BLOB NOT NULL CHECK(length(taskrun_terminal_event_id)=16 AND taskrun_terminal_event_id!=zeroblob(16)),
 taskrun_terminal_version INTEGER NOT NULL CHECK(taskrun_terminal_version>0),
 conversation_terminal_event_id BLOB CHECK(conversation_terminal_event_id IS NULL OR (length(conversation_terminal_event_id)=16 AND conversation_terminal_event_id!=zeroblob(16))),
 conversation_terminal_version INTEGER CHECK(conversation_terminal_version IS NULL OR conversation_terminal_version>0),
 conversation_observed_event_id BLOB NOT NULL CHECK(length(conversation_observed_event_id)=16 AND conversation_observed_event_id!=zeroblob(16)),
 conversation_observed_version INTEGER NOT NULL CHECK(conversation_observed_version>0),
 application_digest BLOB NOT NULL CHECK(length(application_digest)=32 AND application_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((accounting_state=1 AND accounting_digest IS NOT NULL) OR (accounting_state=2 AND accounting_digest IS NULL)),
 CHECK((conversation_terminal_event_id IS NULL)=(conversation_terminal_version IS NULL)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_terminal_settlements(dispatch_attempt_id),
 FOREIGN KEY(taskrun_terminal_event_id) REFERENCES events(event_id),
 FOREIGN KEY(conversation_terminal_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER provider_remote_terminal_applications_immutable BEFORE UPDATE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END;
CREATE TRIGGER provider_remote_terminal_applications_no_delete BEFORE DELETE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END;
"#;

pub(super) fn apply_v61_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V61)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("provider_remote_terminal_applications", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(61)", [])?;
    tx.commit()
}

pub(super) fn v61_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 61..=71)
        || !v60_matches(connection, version)?
        || !table_sql_matches_migration(
            connection,
            "provider_remote_terminal_applications",
            MIGRATION_V61,
        )?
    {
        return Ok(false);
    }
    for (name, expected) in [
        (
            "provider_remote_terminal_applications_immutable",
            "CREATE TRIGGER provider_remote_terminal_applications_immutable BEFORE UPDATE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END",
        ),
        (
            "provider_remote_terminal_applications_no_delete",
            "CREATE TRIGGER provider_remote_terminal_applications_no_delete BEFORE DELETE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END",
        ),
    ] {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) =
            v12_fence_trigger("provider_remote_terminal_applications", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    v61_rows_match(connection)
}

pub(super) fn v61_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_terminal_applications");
    triggers.extend([
        ("provider_remote_terminal_applications_immutable", "CREATE TRIGGER provider_remote_terminal_applications_immutable BEFORE UPDATE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END"),
        ("provider_remote_terminal_applications_no_delete", "CREATE TRIGGER provider_remote_terminal_applications_no_delete BEFORE DELETE ON provider_remote_terminal_applications BEGIN SELECT RAISE(ABORT,'remote terminal application is append only'); END"),
    ]);
    triggers.extend_from_slice(V61_FENCE_TRIGGERS);
}

const V61_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_terminal_applications_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_applications_insert\" AFTER INSERT ON \"provider_remote_terminal_applications\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_applications_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_applications_update\" AFTER UPDATE ON \"provider_remote_terminal_applications\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_applications_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_applications_delete\" AFTER DELETE ON \"provider_remote_terminal_applications\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

include!("v61_remote_terminal_application_match.rs");
include!("v61_remote_terminal_application_successor.rs");
include!("v61_remote_terminal_application_source_match.rs");
/// Exact source identity shared by the v61 application and v62 audit validators.
pub(crate) struct RemoteTerminalSourceMatch<'a> {
    pub(crate) dispatch: &'a [u8],
    pub(crate) taskrun: &'a [u8],
    pub(crate) attempt: &'a [u8],
    pub(crate) request: &'a [u8],
    pub(crate) response: &'a [u8],
    pub(crate) artifact: &'a [u8],
    pub(crate) status: i64,
}
