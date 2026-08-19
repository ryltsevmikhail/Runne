use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult, Transaction, TransactionBehavior,
};

pub(super) const MIGRATION_V19: &str = r#"
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

pub(super) const SNAPSHOT_INSERT_TRIGGER: &str = r#"
CREATE TRIGGER aggregate_state_snapshots_bind_insert
BEFORE INSERT ON aggregate_state_snapshots
WHEN NOT EXISTS(
    SELECT 1 FROM aggregate_streams AS stream
    JOIN events AS event ON event.aggregate_type = stream.aggregate_type
        AND event.aggregate_id = stream.aggregate_id
        AND event.sequence = stream.current_version
        AND event.event_id = NEW.head_event_id
    WHERE stream.aggregate_type = NEW.aggregate_type
        AND stream.aggregate_id = NEW.aggregate_id
        AND stream.current_version = NEW.aggregate_version
        AND stream.last_event_id = NEW.head_event_id
        AND event.integrity_digest = NEW.head_integrity_digest
        AND event.global_position = NEW.head_global_position
        AND NOT EXISTS(SELECT 1 FROM events AS tail
            WHERE tail.aggregate_type = stream.aggregate_type
              AND tail.aggregate_id = stream.aggregate_id
              AND tail.sequence > stream.current_version)
)
BEGIN SELECT RAISE(ABORT, 'aggregate snapshot head mismatch'); END;
"#;

pub(super) const SNAPSHOT_UPDATE_TRIGGER: &str = r#"
CREATE TRIGGER aggregate_state_snapshots_bind_update
BEFORE UPDATE ON aggregate_state_snapshots
WHEN NOT EXISTS(
    SELECT 1 FROM aggregate_streams AS stream
    JOIN events AS event ON event.aggregate_type = stream.aggregate_type
        AND event.aggregate_id = stream.aggregate_id
        AND event.sequence = stream.current_version
        AND event.event_id = NEW.head_event_id
    WHERE stream.aggregate_type = NEW.aggregate_type
        AND stream.aggregate_id = NEW.aggregate_id
        AND stream.current_version = NEW.aggregate_version
        AND stream.last_event_id = NEW.head_event_id
        AND event.integrity_digest = NEW.head_integrity_digest
        AND event.global_position = NEW.head_global_position
        AND NOT EXISTS(SELECT 1 FROM events AS tail
            WHERE tail.aggregate_type = stream.aggregate_type
              AND tail.aggregate_id = stream.aggregate_id
              AND tail.sequence > stream.current_version)
)
BEGIN SELECT RAISE(ABORT, 'aggregate snapshot head mismatch'); END;
"#;

pub(super) fn apply_v19_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V19)?;
    transaction.execute_batch(SNAPSHOT_INSERT_TRIGGER)?;
    transaction.execute_batch(SNAPSHOT_UPDATE_TRIGGER)?;
    super::install_missing_v12_fence_triggers(&transaction)?;
    crate::store::snapshot::legacy::backfill_v17_aggregate_snapshots(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (19)", [])?;
    transaction.commit()
}

pub(super) fn v19_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 19
        || !super::project_workspace_schema::v18_base_matches_with_additional_triggers(
            connection,
            &[
                "aggregate_state_snapshots_bind_insert",
                "aggregate_state_snapshots_bind_update",
            ],
        )?
    {
        return Ok(false);
    }
    let triggers_match = [
        (
            "aggregate_state_snapshots_bind_insert",
            SNAPSHOT_INSERT_TRIGGER,
        ),
        (
            "aggregate_state_snapshots_bind_update",
            SNAPSHOT_UPDATE_TRIGGER,
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
        Ok::<bool, rusqlite::Error>(
            valid
                && actual.is_some_and(|sql| {
                    super::normalize_sql(expected.trim().trim_end_matches(';'))
                        == super::normalize_sql(&sql)
                }),
        )
    })?;
    let mut tables = super::RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "provider_credential_versions",
        "provider_credential_clock_high_water",
        "provider_credential_provisions",
        "provider_credential_effect_bindings",
        "bootstrap_reservations",
        "bootstrap_reservation_tombstones",
        "bootstrap_last_observed_clock",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
        "workspace_identity_history",
        "task_run_workspace_lineage",
        "aggregate_state_snapshots",
    ]);
    Ok(triggers_match
        && super::table_sql_matches_migration(
            connection,
            "aggregate_state_snapshots",
            MIGRATION_V19,
        )?
        && super::index_matches(
            connection,
            "idx_aggregate_state_snapshots_head_position",
            "aggregate_state_snapshots",
            &["head_global_position"],
        )?
        && v17_catalog_matches(connection, &tables)?)
}

fn v17_catalog_matches(connection: &Connection, tables: &[&str]) -> SqliteResult<bool> {
    let actual = connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<SqliteResult<Vec<_>>>()?;
    let mut expected = tables.to_vec();
    expected.sort_unstable();
    if actual
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Ok(false);
    }
    let actual_indexes = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut expected_indexes = super::RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    expected_indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
        "idx_aggregate_state_snapshots_head_position",
    ]);
    expected_indexes.sort_unstable();
    let views: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'",
        [],
        |row| row.get(0),
    )?;
    Ok(views == 0
        && actual_indexes
            .iter()
            .map(String::as_str)
            .eq(expected_indexes.iter().copied()))
}
