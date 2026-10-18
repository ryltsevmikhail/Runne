pub(super) const MIGRATION_V68: &str = include_str!("v68_taskrun_permission.sql");
include!("v68_taskrun_permission_objects.rs");

const V68_ROUTE_TRIGGERS: &[(&str, &str)] = &[
    (
        "taskrun_local_permission_routes_insert_guard",
        "CREATE TRIGGER taskrun_local_permission_routes_insert_guard BEFORE INSERT ON taskrun_local_permission_routes WHEN NEW.route!=2 OR NEW.provenance!=3 OR NEW.cutover_version!=68 OR NOT EXISTS(SELECT 1 FROM taskrun_local_command_attempts a WHERE a.taskrun_id=NEW.taskrun_id AND a.state='preflight' AND a.attempt_id IS NULL AND a.node_id IS NULL AND a.node_epoch IS NULL AND a.fence IS NULL AND a.executable_digest IS NULL AND a.workspace_version IS NULL AND a.admitted_root_version IS NULL AND a.admitted_root_identity IS NULL AND a.trust_epoch IS NULL AND a.trust_revision IS NULL AND a.source_policy_version IS NULL AND a.command_policy_version IS NULL AND a.approval_id IS NULL AND a.managed_area_identity IS NULL) BEGIN SELECT RAISE(ABORT,'new local TaskRun must enter permission route'); END",
    ),
    (
        "taskrun_local_permission_routes_immutable",
        "CREATE TRIGGER taskrun_local_permission_routes_immutable BEFORE UPDATE ON taskrun_local_permission_routes BEGIN SELECT RAISE(ABORT,'local TaskRun permission route is immutable'); END",
    ),
    (
        "taskrun_local_permission_routes_no_delete",
        "CREATE TRIGGER taskrun_local_permission_routes_no_delete BEFORE DELETE ON taskrun_local_permission_routes BEGIN SELECT RAISE(ABORT,'local TaskRun permission route is retained'); END",
    ),
];

const V68_ROUTE_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_taskrun_local_permission_routes_insert",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_local_permission_routes_insert\" AFTER INSERT ON \"taskrun_local_permission_routes\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_local_permission_routes_update",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_local_permission_routes_update\" AFTER UPDATE ON \"taskrun_local_permission_routes\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_local_permission_routes_delete",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_local_permission_routes_delete\" AFTER DELETE ON \"taskrun_local_permission_routes\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

pub(super) fn apply_v68_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    if !v67_matches(&transaction, 67)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let routes = v68_historical_routes(&transaction)?;
    transaction.execute_batch(MIGRATION_V68)?;
    for (taskrun_id, route, provenance) in routes {
        transaction.execute(
            "INSERT INTO taskrun_local_permission_routes(taskrun_id,route,provenance,cutover_version)
             VALUES(?1,?2,?3,68)",
            rusqlite::params![taskrun_id, route, provenance],
        )?;
    }
    for (_, sql) in V68_ROUTE_TRIGGERS
        .iter()
        .chain(V68_ROUTE_FENCE_TRIGGERS)
        .chain(V68_SIDECAR_TRIGGERS)
        .chain(V68_SIDECAR_FENCE_TRIGGERS)
    {
        transaction.execute_batch(sql)?;
    }
    transaction.execute("INSERT INTO schema_version(version) VALUES(68)", [])?;
    if !v68_matches(&transaction, 68)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    transaction.commit()
}

pub(super) fn v68_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 68
        || !v68_marker_matches(connection)?
        || !v64_matches(connection, 68)?
        || !v67_structure_matches(connection)?
        || !table_sql_matches_migration(
            connection,
            "taskrun_local_permission_routes",
            MIGRATION_V68,
        )?
        || !v68_routes_match(connection)?
        || !v68_sidecars_match(connection)?
        || !v68_foreign_keys_match(connection)?
    {
        return Ok(false);
    }
    for (name, sql) in V68_ROUTE_TRIGGERS
        .iter()
        .chain(V68_ROUTE_FENCE_TRIGGERS)
        .chain(V68_SIDECAR_TRIGGERS)
        .chain(V68_SIDECAR_FENCE_TRIGGERS)
    {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn v68_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    v67_add_schema_extensions(tables, indexes, triggers);
    tables.push("taskrun_local_permission_routes");
    tables.extend_from_slice(V68_SIDECAR_TABLES);
    triggers.extend_from_slice(V68_ROUTE_TRIGGERS);
    triggers.extend_from_slice(V68_ROUTE_FENCE_TRIGGERS);
    triggers.extend_from_slice(V68_SIDECAR_TRIGGERS);
    triggers.extend_from_slice(V68_SIDECAR_FENCE_TRIGGERS);
}

fn v68_marker_matches(connection: &Connection) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0)
         FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (68, 1, 68, 2346) | (68, 1, 67, 2327)))
}

fn v68_foreign_keys_match(connection: &Connection) -> SqliteResult<bool> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    Ok(statement.query([])?.next()?.is_none())
}

fn v68_routes_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_local_command_attempts a
         LEFT JOIN taskrun_local_permission_routes r USING(taskrun_id)
         WHERE r.taskrun_id IS NULL OR r.cutover_version!=68
           OR (r.route=1 AND r.provenance=1 AND (
               a.executable_digest IS NULL OR a.workspace_version IS NULL
               OR a.admitted_root_version IS NULL OR a.admitted_root_identity IS NULL
               OR a.trust_epoch IS NULL OR a.trust_revision IS NULL
               OR a.source_policy_version!=2 OR a.command_policy_version!=1
               OR a.approval_id IS NULL))
           OR (r.route=1 AND r.provenance=2 AND a.state NOT IN
               ('completed','cancelled','denied','no_effect_terminal'))
           OR (r.route=2 AND r.provenance=3 AND (
               a.executable_digest IS NOT NULL OR a.workspace_version IS NOT NULL
               OR a.admitted_root_version IS NOT NULL OR a.admitted_root_identity IS NOT NULL
               OR a.trust_epoch IS NOT NULL OR a.trust_revision IS NOT NULL
               OR a.source_policy_version IS NOT NULL OR a.command_policy_version IS NOT NULL
               OR a.approval_id IS NOT NULL))
           OR (r.route NOT IN (1,2) OR r.provenance NOT IN (1,2,3))",
        [],
        |row| row.get(0),
    )?;
    let orphaned: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_local_permission_routes r
         LEFT JOIN taskrun_local_command_attempts a USING(taskrun_id)
         WHERE a.taskrun_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if invalid != 0 || orphaned != 0 {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT r.taskrun_id,r.provenance,a.state FROM taskrun_local_permission_routes r
         JOIN taskrun_local_command_attempts a USING(taskrun_id) WHERE r.route=1",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (taskrun_id, provenance, state) = row?;
        let matches = match provenance {
            1 => retained_legacy_bound_matches(connection, &taskrun_id, &state)?,
            2 => v68_legacy_terminal_matches(connection, &taskrun_id, &state)?,
            _ => false,
        };
        if !matches {
            return Ok(false);
        }
    }
    let mut statement = connection.prepare(
        "SELECT r.taskrun_id,a.conversation_id,a.workspace_id,a.command_digest
         FROM taskrun_local_permission_routes r
         JOIN taskrun_local_command_attempts a USING(taskrun_id)",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    for row in rows {
        let (taskrun_id, conversation_id, workspace_id, command_digest) = row?;
        if !v68_submitted_origin_matches(
            connection,
            &taskrun_id,
            &conversation_id,
            &workspace_id,
            &command_digest,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v68_submitted_origin_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    conversation_id: &[u8],
    workspace_id: &[u8],
    command_digest: &[u8],
) -> SqliteResult<bool> {
    let Ok(taskrun_id) = <[u8; 16]>::try_from(taskrun_id) else {
        return Ok(false);
    };
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection,
        runne_domain::id::TaskRunId::from_bytes(taskrun_id),
    );
    let Ok(Some(origin)) = origin else {
        return Ok(false);
    };
    Ok(origin.conversation_id.as_bytes() == conversation_id
        && origin.workspace_id.as_bytes() == workspace_id
        && origin
            .input
            .local_command()
            .is_some_and(|command| command.intent_digest().as_slice() == command_digest))
}

fn v68_has_only_submission_event(connection: &Connection, taskrun_id: &[u8]) -> SqliteResult<bool> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence!=1",
        [taskrun_id],
        |row| row.get(0),
    )?;
    let receipts: i64 = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1)
              +(SELECT COUNT(*) FROM taskrun_no_effect_release_receipts WHERE taskrun_id=?1)",
        [taskrun_id],
        |row| row.get(0),
    )?;
    Ok(count == 0 && receipts == 0)
}
