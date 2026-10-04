include!("v57_taskrun_unknown_successor_match.rs");

pub(super) const MIGRATION_V57: &str = r#"
CREATE TABLE taskrun_unknown_successor_receipts (
 predecessor_taskrun_id BLOB PRIMARY KEY CHECK(length(predecessor_taskrun_id)=16 AND predecessor_taskrun_id!=zeroblob(16)),
 successor_taskrun_id BLOB NOT NULL UNIQUE CHECK(length(successor_taskrun_id)=16 AND successor_taskrun_id!=zeroblob(16) AND successor_taskrun_id!=predecessor_taskrun_id),
 predecessor_attempt_id BLOB NOT NULL CHECK(length(predecessor_attempt_id)=16 AND predecessor_attempt_id!=zeroblob(16)),
 predecessor_dispatch_attempt_id BLOB CHECK(predecessor_dispatch_attempt_id IS NULL OR (length(predecessor_dispatch_attempt_id)=16 AND predecessor_dispatch_attempt_id!=zeroblob(16))),
 predecessor_event_id BLOB CHECK(predecessor_event_id IS NULL OR (length(predecessor_event_id)=16 AND predecessor_event_id!=zeroblob(16))),
 predecessor_event_version INTEGER CHECK(predecessor_event_version IS NULL OR predecessor_event_version>0),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16 AND conversation_id!=zeroblob(16)),
 generation_superseded_event_id BLOB UNIQUE CHECK(generation_superseded_event_id IS NULL OR (length(generation_superseded_event_id)=16 AND generation_superseded_event_id!=zeroblob(16))),
 generation_superseded_version INTEGER CHECK(generation_superseded_version IS NULL OR generation_superseded_version>0),
 successor_submit_event_id BLOB NOT NULL UNIQUE CHECK(length(successor_submit_event_id)=16 AND successor_submit_event_id!=zeroblob(16)),
 successor_submit_version INTEGER NOT NULL CHECK(successor_submit_version>0),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)),
 principal_digest BLOB NOT NULL CHECK(length(principal_digest)=32 AND principal_digest!=zeroblob(32)),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 origin_kind TEXT NOT NULL CHECK(origin_kind IN ('canonical_workspace','text_only')),
 project_id BLOB CHECK(project_id IS NULL OR (length(project_id)=16 AND project_id!=zeroblob(16))),
 origin_operation INTEGER NOT NULL CHECK(origin_operation=24),
 acknowledgement_code TEXT NOT NULL CHECK(acknowledgement_code='duplicate_execution_and_cost_v1'),
 acknowledgement_version INTEGER NOT NULL CHECK(acknowledgement_version=1),
 acknowledgement_digest BLOB NOT NULL CHECK(length(acknowledgement_digest)=32 AND acknowledgement_digest!=zeroblob(32)),
 predecessor_input_digest BLOB NOT NULL CHECK(length(predecessor_input_digest)=32 AND predecessor_input_digest!=zeroblob(32)),
 typed_input_digest BLOB NOT NULL CHECK(length(typed_input_digest)=32 AND typed_input_digest!=zeroblob(32)),
 provider_id TEXT CHECK(provider_id IS NULL OR length(provider_id) BETWEEN 1 AND 128),
 profile_id TEXT CHECK(profile_id IS NULL OR length(profile_id) BETWEEN 1 AND 128),
 profile_digest BLOB CHECK(profile_digest IS NULL OR (length(profile_digest)=32 AND profile_digest!=zeroblob(32))),
 model_id TEXT CHECK(model_id IS NULL OR length(model_id) BETWEEN 1 AND 128),
 model_revision TEXT CHECK(model_revision IS NULL OR length(model_revision) BETWEEN 1 AND 128),
 model_ref_digest BLOB CHECK(model_ref_digest IS NULL OR (length(model_ref_digest)=32 AND model_ref_digest!=zeroblob(32))),
 occupation_fence INTEGER NOT NULL CHECK(occupation_fence>0),
 occupation_release_event_id BLOB NOT NULL CHECK(length(occupation_release_event_id)=16 AND occupation_release_event_id!=zeroblob(16)),
 occupation_release_version INTEGER NOT NULL CHECK(occupation_release_version>0),
 occupation_release_reason TEXT NOT NULL CHECK(length(occupation_release_reason) BETWEEN 1 AND 64),
 command_id BLOB NOT NULL UNIQUE CHECK(length(command_id)=16 AND command_id!=zeroblob(16)),
 idempotency_key_digest BLOB NOT NULL CHECK(length(idempotency_key_digest)=32 AND idempotency_key_digest!=zeroblob(32)),
 command_fingerprint BLOB NOT NULL CHECK(length(command_fingerprint)=32 AND command_fingerprint!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 CHECK((predecessor_event_id IS NULL)=(predecessor_event_version IS NULL)),
 CHECK((generation_superseded_event_id IS NULL)=(generation_superseded_version IS NULL)),
 CHECK((predecessor_dispatch_attempt_id IS NULL AND provider_id IS NULL AND profile_id IS NULL
       AND profile_digest IS NULL AND model_id IS NULL AND model_revision IS NULL AND model_ref_digest IS NULL)
    OR (predecessor_dispatch_attempt_id IS NOT NULL AND provider_id IS NOT NULL AND profile_id IS NOT NULL
       AND profile_digest IS NOT NULL AND model_id IS NOT NULL AND model_revision IS NOT NULL AND model_ref_digest IS NOT NULL)),
 CHECK((origin_kind='canonical_workspace' AND project_id IS NOT NULL)
    OR (origin_kind='text_only' AND project_id IS NULL)),
 FOREIGN KEY(predecessor_dispatch_attempt_id) REFERENCES provider_execution_admissions(dispatch_attempt_id),
 FOREIGN KEY(predecessor_event_id) REFERENCES events(event_id),
 FOREIGN KEY(generation_superseded_event_id) REFERENCES events(event_id),
 FOREIGN KEY(successor_submit_event_id) REFERENCES events(event_id),
 FOREIGN KEY(occupation_release_event_id) REFERENCES events(event_id),
 FOREIGN KEY(command_id) REFERENCES command_receipts(command_id)
);
CREATE TRIGGER taskrun_unknown_successor_receipts_immutable BEFORE UPDATE ON taskrun_unknown_successor_receipts BEGIN SELECT RAISE(ABORT,'unknown successor receipt is append only'); END;
CREATE TRIGGER taskrun_unknown_successor_receipts_no_delete BEFORE DELETE ON taskrun_unknown_successor_receipts BEGIN SELECT RAISE(ABORT,'unknown successor receipt is append only'); END;
"#;

pub(super) fn apply_v57_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V57)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("taskrun_unknown_successor_receipts", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(57)", [])?;
    tx.commit()
}

pub(super) fn v57_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 57..=63) {
        return Ok(false);
    }
    if !v56_matches(connection, version)? {
        return Ok(false);
    }
    if !table_sql_matches_migration(
        connection,
        "taskrun_unknown_successor_receipts",
        MIGRATION_V57,
    )? {
        return Ok(false);
    }
    for (name, expected) in V57_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("taskrun_unknown_successor_receipts", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    let matches = v57_successor_receipts_match(connection)?;
    Ok(matches)
}

pub(super) fn v57_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("taskrun_unknown_successor_receipts");
    triggers.extend_from_slice(V57_TRIGGERS);
    triggers.extend_from_slice(V57_FENCE_TRIGGERS);
}

const V57_TRIGGERS: &[(&str, &str)] = &[
    (
        "taskrun_unknown_successor_receipts_immutable",
        "CREATE TRIGGER taskrun_unknown_successor_receipts_immutable BEFORE UPDATE ON taskrun_unknown_successor_receipts BEGIN SELECT RAISE(ABORT,'unknown successor receipt is append only'); END",
    ),
    (
        "taskrun_unknown_successor_receipts_no_delete",
        "CREATE TRIGGER taskrun_unknown_successor_receipts_no_delete BEFORE DELETE ON taskrun_unknown_successor_receipts BEGIN SELECT RAISE(ABORT,'unknown successor receipt is append only'); END",
    ),
];

const V57_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_taskrun_unknown_successor_receipts_insert",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_unknown_successor_receipts_insert\" AFTER INSERT ON \"taskrun_unknown_successor_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_unknown_successor_receipts_update",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_unknown_successor_receipts_update\" AFTER UPDATE ON \"taskrun_unknown_successor_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_unknown_successor_receipts_delete",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_unknown_successor_receipts_delete\" AFTER DELETE ON \"taskrun_unknown_successor_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];
