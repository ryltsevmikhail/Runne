use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult, Transaction, TransactionBehavior,
};

pub(super) const MIGRATION_V18: &str = r#"
CREATE TABLE aggregate_state_snapshots (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    codec_version INTEGER NOT NULL CHECK(codec_version = 1),
    aggregate_version INTEGER NOT NULL CHECK(aggregate_version > 0),
    event_sequence INTEGER NOT NULL CHECK(event_sequence = aggregate_version),
    head_event_id BLOB NOT NULL CHECK(length(head_event_id) = 16),
    head_integrity_digest BLOB NOT NULL CHECK(length(head_integrity_digest) = 32),
    projection_bytes BLOB NOT NULL CHECK(length(projection_bytes) BETWEEN 1 AND 524288),
    projection_digest BLOB NOT NULL CHECK(length(projection_digest) = 32),
    promotion_codec_version INTEGER NOT NULL CHECK(promotion_codec_version = 1),
    promotion_projection_bytes BLOB NOT NULL CHECK(length(promotion_projection_bytes) BETWEEN 1 AND 524288),
    promotion_projection_digest BLOB NOT NULL CHECK(length(promotion_projection_digest) = 32),
    head_global_position INTEGER NOT NULL CHECK(head_global_position > 0),
    snapshot_integrity_digest BLOB NOT NULL CHECK(length(snapshot_integrity_digest) = 32),
    PRIMARY KEY(aggregate_type, aggregate_id),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES aggregate_streams(aggregate_type, aggregate_id)
        ON DELETE RESTRICT
);
CREATE INDEX idx_aggregate_state_snapshots_head_position
    ON aggregate_state_snapshots(head_global_position);
"#;

const DROP_V17_SNAPSHOT: &str = r#"
DROP TRIGGER aggregate_state_snapshots_bind_insert;
DROP TRIGGER aggregate_state_snapshots_bind_update;
DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_insert;
DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_update;
DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_delete;
DROP TABLE aggregate_state_snapshots;
"#;

/// Applies V18 directly from V16 or replaces a locally-created V17 snapshot
/// catalog only after replay validates every source history. V17 was never a
/// published boundary, so callers from V16 must not create it as a waypoint.
pub(super) fn apply_v18_migration(connection: &Connection, replaces_v17: bool) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    if replaces_v17 {
        transaction.execute_batch(DROP_V17_SNAPSHOT)?;
    }
    transaction.execute_batch(MIGRATION_V18)?;
    transaction.execute_batch(super::replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER)?;
    transaction.execute_batch(super::replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER)?;
    super::install_missing_v12_fence_triggers(&transaction)?;
    crate::store::snapshot::backfill_all_aggregate_snapshots(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (18)", [])?;
    transaction.commit()
}

pub(super) fn v18_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 18
        || !super::project_workspace_schema::v16_base_matches_with_additional_triggers(
            connection,
            &[
                "aggregate_state_snapshots_bind_insert",
                "aggregate_state_snapshots_bind_update",
            ],
        )?
        || !super::table_sql_matches_migration(
            connection,
            "aggregate_state_snapshots",
            MIGRATION_V18,
        )?
        || !super::index_matches(
            connection,
            "idx_aggregate_state_snapshots_head_position",
            "aggregate_state_snapshots",
            &["head_global_position"],
        )?
    {
        return Ok(false);
    }
    Ok(triggers_match(connection)? && catalog_matches(connection)?)
}

fn triggers_match(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "aggregate_state_snapshots_bind_insert",
            super::replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER,
        ),
        (
            "aggregate_state_snapshots_bind_update",
            super::replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER,
        ),
    ]
    .into_iter()
    .try_fold(true, |valid, (name, expected)| {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(valid
            && actual.is_some_and(|sql| {
                super::normalize_sql(expected.trim().trim_end_matches(';'))
                    == super::normalize_sql(&sql)
            }))
    })
}

fn catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let mut tables = super::RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
        "workspace_identity_history",
        "task_run_workspace_lineage",
        "aggregate_state_snapshots",
    ]);
    let actual = connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<SqliteResult<Vec<_>>>()?;
    tables.sort_unstable();
    if actual.iter().map(String::as_str).ne(tables.iter().copied()) {
        return Ok(false);
    }
    let actual_indexes = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut expected = super::RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    expected.push("idx_aggregate_state_snapshots_head_position");
    expected.sort_unstable();
    let views: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'",
        [],
        |row| row.get(0),
    )?;
    Ok(views == 0
        && actual_indexes
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()))
}
