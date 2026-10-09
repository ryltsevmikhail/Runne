pub(super) const MIGRATION_V49: &str = r#"
CREATE TABLE taskrun_terminal_settlement_receipts (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 node_id BLOB NOT NULL CHECK(length(node_id)=16),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 terminal_event_id BLOB NOT NULL UNIQUE CHECK(length(terminal_event_id)=16),
 terminal_version INTEGER NOT NULL CHECK(terminal_version>0),
 PRIMARY KEY(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence),
 FOREIGN KEY(terminal_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER taskrun_terminal_settlement_immutable BEFORE UPDATE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END;
CREATE TRIGGER taskrun_terminal_settlement_no_delete BEFORE DELETE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END;
"#;

pub(super) fn apply_v49_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V49)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("taskrun_terminal_settlement_receipts", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(49)", [])?;
    tx.commit()
}

pub(super) fn v49_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 49..=68) {
        return Ok(false);
    }
    if !v48_matches(connection, version)? {
        return Ok(false);
    }
    let expected = MIGRATION_V49
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE taskrun_terminal_settlement_receipts "))
        .expect("V49 settlement DDL is frozen");
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_terminal_settlement_receipts'",
        [], |row| row.get(0),
    ).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(expected)) {
        return Ok(false);
    }
    for (name, expected) in [
        (
            "taskrun_terminal_settlement_immutable",
            "CREATE TRIGGER taskrun_terminal_settlement_immutable BEFORE UPDATE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END",
        ),
        (
            "taskrun_terminal_settlement_no_delete",
            "CREATE TRIGGER taskrun_terminal_settlement_no_delete BEFORE DELETE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END",
        ),
    ] {
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
        let (name, expected) = v12_fence_trigger("taskrun_terminal_settlement_receipts", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |r| r.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    let successor_release = if version >= 57 {
        "OR EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts u
           JOIN events release_event ON release_event.event_id=u.occupation_release_event_id
           WHERE u.predecessor_taskrun_id=o.taskrun_id AND u.occupation_fence=o.fence
             AND u.predecessor_attempt_id=o.attempt_id
             AND u.occupation_release_reason='user_supersession'
             AND u.occupation_release_event_id=o.release_event_id
             AND u.occupation_release_version=release_event.sequence
             AND release_event.aggregate_type=1 AND release_event.aggregate_id=o.taskrun_id)"
    } else {
        ""
    };
    let sql = format!(
        "SELECT (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts r
         LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)
         LEFT JOIN taskrun_assignments a USING(taskrun_id,fence)
         LEFT JOIN events e ON e.event_id=r.terminal_event_id
         LEFT JOIN aggregate_streams s ON s.aggregate_type=1 AND s.aggregate_id=r.taskrun_id
         WHERE o.taskrun_id IS NULL OR a.taskrun_id IS NULL OR e.event_id IS NULL
           OR o.state!='released' OR o.release_event_id!=r.terminal_event_id
           OR o.dispatch_intent NOT IN ('present','absent') OR o.attempt_id!=r.attempt_id
           OR o.node_id!=r.node_id OR o.node_epoch!=r.node_epoch
           OR a.attempt_id!=r.attempt_id OR a.node_id!=r.node_id OR a.node_epoch!=r.node_epoch
           OR e.aggregate_type!=1 OR e.aggregate_id!=r.taskrun_id
           OR e.sequence!=r.terminal_version OR s.current_version!=r.terminal_version
           OR s.last_event_id!=r.terminal_event_id) + (SELECT COUNT(*) FROM taskrun_assignment_occupations o
         LEFT JOIN taskrun_no_effect_release_receipts n USING(taskrun_id,fence)
         LEFT JOIN taskrun_dispatch_intents i USING(taskrun_id,fence)
         LEFT JOIN taskrun_terminal_settlement_receipts t USING(taskrun_id,fence)
         WHERE o.state='released' AND NOT (
           (n.command_id IS NOT NULL AND i.taskrun_id IS NULL AND o.dispatch_intent='absent')
           OR (t.taskrun_id IS NOT NULL AND t.terminal_event_id=o.release_event_id
               AND o.dispatch_intent IN ('present','absent')) {successor_release}))"
    );
    let invalid: i64 = connection.query_row(&sql, [], |row| row.get(0))?;
    if invalid != 0 {
        return Ok(false);
    }
    let mut stmt = connection.prepare(
        "SELECT e.payload,o.dispatch_intent,r.taskrun_id,r.attempt_id,r.node_id,r.node_epoch,
                r.fence,r.terminal_event_id,r.terminal_version
         FROM taskrun_terminal_settlement_receipts r JOIN events e ON e.event_id=r.terminal_event_id JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Vec<u8>>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;
    for row in rows {
        let (payload, intent, taskrun_id, attempt_id, node_id, node_epoch, fence, terminal_event_id, terminal_version) =
            row?;
        let Ok(event) = TaskRunEventCodec.decode(&payload) else {
            return Ok(false);
        };
        let valid = match intent.as_str() {
            "present" => matches!(
                event,
                runne_domain::task_run::TaskRunEvent::TaskRunCompleted { .. }
                    | runne_domain::task_run::TaskRunEvent::TaskRunFailed { .. }
                    | runne_domain::task_run::TaskRunEvent::TaskRunCancelled
                    | runne_domain::task_run::TaskRunEvent::CancellationCompleted
                    | runne_domain::task_run::TaskRunEvent::Unrecoverable
            ),
            "absent" => {
                matches!(event,
                    runne_domain::task_run::TaskRunEvent::TaskRunFailed { ref reason }
                        if matches!(reason.as_str(), "dispatch_not_started" | "provider_execution_rejected" | "interrupted_by_restart")
                ) || (matches!(
                    event,
                    runne_domain::task_run::TaskRunEvent::TaskRunCancelled
                        | runne_domain::task_run::TaskRunEvent::CancellationCompleted
                ) && (version < 51
                    || local_cancellation_matches(
                        connection,
                        &taskrun_id,
                        &attempt_id,
                        &node_id,
                        node_epoch,
                        fence,
                        &event,
                    )?))
                    || (version >= 51
                        && local_terminal_proof_matches(
                            connection,
                            &taskrun_id,
                            &attempt_id,
                            &node_id,
                            node_epoch,
                            fence,
                            &event,
                        )?)
                    || (version >= 53
                        && local_stop_terminal_proof_matches(
                            connection,
                            &taskrun_id,
                            &attempt_id,
                            &node_id,
                            node_epoch,
                            fence,
                            &event,
                        )?)
                    || (version >= 68
                        && matches!(
                            &event,
                            runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason }
                                if reason == "local_command_policy_stopped_v1"
                        )
                        && crate::store::taskrun_local_command::effects_proof::policy_stop_reopen_proven(
                            connection,
                            &taskrun_id,
                            &attempt_id,
                            &node_id,
                            node_epoch,
                            fence,
                        )
                        .map_err(|_| rusqlite::Error::InvalidQuery)?)
                    || (version >= 68
                        && v68_current_route_terminal_matches(
                            connection,
                            &taskrun_id,
                            &attempt_id,
                            &node_id,
                            node_epoch,
                            fence,
                            &terminal_event_id,
                            terminal_version,
                            &event,
                        )?)
            }
            _ => false,
        };
        if !valid {
            return Ok(false);
        }
    }
    if version >= 51 && !local_no_effect_releases_match(connection)? {
        return Ok(false);
    }
    Ok(true)
}
