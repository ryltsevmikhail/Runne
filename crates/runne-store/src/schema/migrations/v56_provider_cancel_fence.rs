include!("v56_cancel_migration.rs");

type V56CancelFenceRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

pub(super) const MIGRATION_V56: &str = r#"
CREATE TABLE taskrun_provider_cancel_fences (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 cancellation_event_id BLOB NOT NULL UNIQUE CHECK(length(cancellation_event_id)=16 AND cancellation_event_id!=zeroblob(16)),
 cancellation_version INTEGER NOT NULL CHECK(cancellation_version>0),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_execution_admissions(dispatch_attempt_id),
 FOREIGN KEY(cancellation_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER taskrun_provider_cancel_fences_immutable BEFORE UPDATE ON taskrun_provider_cancel_fences BEGIN SELECT RAISE(ABORT,'TaskRun provider cancel fence is append only'); END;
CREATE TRIGGER taskrun_provider_cancel_fences_no_delete BEFORE DELETE ON taskrun_provider_cancel_fences BEGIN SELECT RAISE(ABORT,'TaskRun provider cancel fence is append only'); END;
"#;

pub(super) fn apply_v56_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V56)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("taskrun_provider_cancel_fences", operation).1)?;
    }
    backfill_v56_cancel_fences(&tx)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(56)", [])?;
    tx.commit()
}

pub(super) fn v56_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 56..=71) {
        return Ok(false);
    }
    if !v55_matches(connection, version)? {
        return Ok(false);
    }
    if !table_sql_matches_migration(connection, "taskrun_provider_cancel_fences", MIGRATION_V56)? {
        return Ok(false);
    }
    for (name, expected) in V56_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("taskrun_provider_cancel_fences", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    let a = v56_cancel_fences_match(connection)?;
    let allow_v64_d2 = v64_d2_extensions_present(connection)?;
    let b = v56_cancel_fences_cover_cancellations(connection, allow_v64_d2)?;
    Ok(a && b)
}

fn v64_d2_extensions_present(connection: &Connection) -> SqliteResult<bool> {
    let current: Option<i64> = connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .optional()?;
    let installed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='taskrun_provider_round_bindings')
         AND EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='provider_terminal_application_kinds')",
        [],
        |row| row.get(0),
    )?;
    Ok(current.is_some_and(|version| version >= 64) && installed)
}

fn v56_cancel_fences_match(connection: &Connection) -> SqliteResult<bool> {
    let rows: Vec<V56CancelFenceRow> = {
        let mut statement = connection.prepare(
            "SELECT taskrun_id,taskrun_attempt_id,dispatch_attempt_id,cancellation_event_id,cancellation_version
             FROM taskrun_provider_cancel_fences",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?
    };
    for (taskrun, attempt, dispatch, event, version) in rows {
        let matches: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions admission
             JOIN events cancel ON cancel.event_id=?4
             WHERE admission.dispatch_attempt_id=?3 AND admission.taskrun_id=?1
               AND admission.execution_attempt_id=?2 AND cancel.aggregate_type=1
               AND cancel.aggregate_id=?1 AND cancel.sequence=?5)",
            rusqlite::params![taskrun, attempt, dispatch, event, version],
            |row| row.get(0),
        )?;
        if !matches
            || !v56_cancel_event_and_attempt_match(connection, &taskrun, &attempt, &event, version)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v56_cancel_event_and_attempt_match(
    connection: &Connection,
    taskrun: &[u8],
    attempt: &[u8],
    event_id: &[u8],
    version: i64,
) -> SqliteResult<bool> {
    let event: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1
             AND aggregate_id=?2 AND sequence=?3",
            rusqlite::params![event_id, taskrun, version],
            |row| row.get(0),
        )
        .optional()?;
    let Some(event) = event else { return Ok(false) };
    let decoded: Result<runne_domain::task_run::TaskRunEvent, _> =
        crate::codec::StoreCodec::decode(&crate::codec::TaskRunEventCodec, &event);
    if !matches!(
        decoded,
        Ok(runne_domain::task_run::TaskRunEvent::CancellationRequested)
    ) {
        return Ok(false);
    }
    let taskrun = match <[u8; 16]>::try_from(taskrun) {
        Ok(bytes) => runne_domain::id::TaskRunId::from_bytes(bytes),
        Err(_) => return Ok(false),
    };
    let prefix_version = match version
        .checked_sub(1)
        .and_then(|value| u64::try_from(value).ok())
    {
        Some(value) => value,
        None => return Ok(false),
    };
    let active = crate::store::taskrun_claim::active_attempt_at_verified_version(
        connection,
        taskrun,
        prefix_version,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(active.is_some_and(|active| active.as_bytes() == attempt))
}

const V56_TRIGGERS: &[(&str, &str)] = &[
    (
        "taskrun_provider_cancel_fences_immutable",
        "CREATE TRIGGER taskrun_provider_cancel_fences_immutable BEFORE UPDATE ON taskrun_provider_cancel_fences BEGIN SELECT RAISE(ABORT,'TaskRun provider cancel fence is append only'); END",
    ),
    (
        "taskrun_provider_cancel_fences_no_delete",
        "CREATE TRIGGER taskrun_provider_cancel_fences_no_delete BEFORE DELETE ON taskrun_provider_cancel_fences BEGIN SELECT RAISE(ABORT,'TaskRun provider cancel fence is append only'); END",
    ),
];

pub(super) fn v56_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("taskrun_provider_cancel_fences");
    triggers.extend_from_slice(V56_TRIGGERS);
    triggers.extend_from_slice(V56_FENCE_TRIGGERS);
}

const V56_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_taskrun_provider_cancel_fences_insert",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_cancel_fences_insert\" AFTER INSERT ON \"taskrun_provider_cancel_fences\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_provider_cancel_fences_update",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_cancel_fences_update\" AFTER UPDATE ON \"taskrun_provider_cancel_fences\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_provider_cancel_fences_delete",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_cancel_fences_delete\" AFTER DELETE ON \"taskrun_provider_cancel_fences\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];
