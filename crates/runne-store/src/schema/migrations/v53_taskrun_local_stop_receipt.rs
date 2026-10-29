pub(super) const MIGRATION_V53: &str = r#"
CREATE TABLE taskrun_local_command_stop_receipts (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 historic_node_id BLOB NOT NULL CHECK(length(historic_node_id)=16 AND historic_node_id!=zeroblob(16)),
 historic_node_epoch INTEGER NOT NULL CHECK(historic_node_epoch>0),
 proof_node_id BLOB NOT NULL CHECK(length(proof_node_id)=16 AND proof_node_id!=zeroblob(16)),
 proof_node_epoch INTEGER NOT NULL CHECK(proof_node_epoch>historic_node_epoch),
 managed_area_identity BLOB NOT NULL CHECK(length(managed_area_identity)=100),
 command_digest BLOB NOT NULL CHECK(length(command_digest)=32 AND command_digest!=zeroblob(32)),
 stop_kind TEXT NOT NULL CHECK(stop_kind='outcome_unknown'),
 terminal_event_id BLOB NOT NULL UNIQUE CHECK(length(terminal_event_id)=16 AND terminal_event_id!=zeroblob(16)),
 terminal_version INTEGER NOT NULL CHECK(terminal_version>0),
 PRIMARY KEY(taskrun_id,fence),
 UNIQUE(taskrun_id,attempt_id),
 CHECK(proof_node_id=historic_node_id),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_terminal_settlement_receipts(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignment_occupations(taskrun_id,fence),
 FOREIGN KEY(taskrun_id) REFERENCES taskrun_local_command_attempts(taskrun_id),
 FOREIGN KEY(terminal_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER taskrun_local_command_stop_receipts_immutable BEFORE UPDATE ON taskrun_local_command_stop_receipts BEGIN SELECT RAISE(ABORT,'local stop receipt is append only'); END;
CREATE TRIGGER taskrun_local_command_stop_receipts_no_delete BEFORE DELETE ON taskrun_local_command_stop_receipts BEGIN SELECT RAISE(ABORT,'local stop receipt is append only'); END;
"#;

pub(super) fn v53_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 53 || !v53_base_matches(connection, version)? {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn v53_base_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 53..=71) {
        return Ok(false);
    }
    if !v52_base_matches(connection, version)? {
        return Ok(false);
    }
    if !table_sql_matches_migration(
        connection,
        "taskrun_local_command_stop_receipts",
        MIGRATION_V53,
    )? {
        return Ok(false);
    }
    for (name, expected) in V53_STOP_TRIGGERS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("taskrun_local_command_stop_receipts", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    let matches = local_stop_receipts_match(connection)?;
    Ok(matches)
}

const V53_STOP_TABLES: &[&str] = &["taskrun_local_command_stop_receipts"];
const V53_STOP_TRIGGERS: &[(&str, &str)] = &[
    (
        "taskrun_local_command_stop_receipts_immutable",
        "CREATE TRIGGER taskrun_local_command_stop_receipts_immutable BEFORE UPDATE ON taskrun_local_command_stop_receipts BEGIN SELECT RAISE(ABORT,'local stop receipt is append only'); END",
    ),
    (
        "taskrun_local_command_stop_receipts_no_delete",
        "CREATE TRIGGER taskrun_local_command_stop_receipts_no_delete BEFORE DELETE ON taskrun_local_command_stop_receipts BEGIN SELECT RAISE(ABORT,'local stop receipt is append only'); END",
    ),
];

pub(super) fn apply_v53_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V53)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("taskrun_local_command_stop_receipts", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(53)", [])?;
    tx.commit()
}

pub(super) fn v53_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.extend_from_slice(V53_STOP_TABLES);
    triggers.extend_from_slice(V53_STOP_TRIGGERS);
    triggers.extend([
        ("schema_v12_fence_taskrun_local_command_stop_receipts_insert", "CREATE TRIGGER \"schema_v12_fence_taskrun_local_command_stop_receipts_insert\" AFTER INSERT ON \"taskrun_local_command_stop_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_taskrun_local_command_stop_receipts_update", "CREATE TRIGGER \"schema_v12_fence_taskrun_local_command_stop_receipts_update\" AFTER UPDATE ON \"taskrun_local_command_stop_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_taskrun_local_command_stop_receipts_delete", "CREATE TRIGGER \"schema_v12_fence_taskrun_local_command_stop_receipts_delete\" AFTER DELETE ON \"taskrun_local_command_stop_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
    ]);
}
