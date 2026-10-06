pub(super) const MIGRATION_V43: &str = r#"
CREATE TABLE taskrun_assignment_occupations (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL UNIQUE CHECK(length(attempt_id)=16),
 node_id BLOB NOT NULL CHECK(length(node_id)=16),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms>0),
 state TEXT NOT NULL CHECK(state IN ('active','released')),
 dispatch_intent TEXT NOT NULL CHECK(dispatch_intent IN ('unknown','absent','present')),
 release_event_id BLOB UNIQUE CHECK(release_event_id IS NULL OR length(release_event_id)=16),
 PRIMARY KEY(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence)
);
CREATE INDEX taskrun_assignment_occupations_capacity ON taskrun_assignment_occupations(node_id,state);
CREATE TABLE taskrun_assignment_lease_renewals (
 renewal_id BLOB PRIMARY KEY CHECK(length(renewal_id)=16),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 node_id BLOB NOT NULL CHECK(length(node_id)=16),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 lease_duration_ms INTEGER NOT NULL CHECK(lease_duration_ms BETWEEN 1 AND 300000),
 lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms>0),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence)
);
CREATE TRIGGER taskrun_assignment_lease_renewals_immutable
BEFORE UPDATE ON taskrun_assignment_lease_renewals
BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END;
CREATE TRIGGER taskrun_assignment_lease_renewals_no_delete
BEFORE DELETE ON taskrun_assignment_lease_renewals
BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END;
CREATE TRIGGER global_command_id_from_lease_renewals_v43
BEFORE INSERT ON taskrun_assignment_lease_renewals
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.renewal_id)
 OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.renewal_id)
 OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.renewal_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_command_receipts_v43
BEFORE INSERT ON command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_project_workspace_receipts_v43
BEFORE INSERT ON project_workspace_command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v43
BEFORE INSERT ON taskrun_claim_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent)
 SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,'active','unknown' FROM taskrun_assignments;
"#;

pub(super) fn apply_v43_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V43)?;
    for table in [
        "taskrun_assignment_occupations",
        "taskrun_assignment_lease_renewals",
    ] {
        for operation in ["insert", "update", "delete"] {
            transaction.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    transaction.execute("INSERT INTO schema_version(version) VALUES(43)", [])?;
    transaction.commit()
}

pub(super) fn v43_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !(43..=65).contains(&version) {
        return Ok(false);
    }
    if !v42_structure_matches(connection, true)? {
        return Ok(false);
    }
    let marker: (i64,i64,i64,i64) = connection.query_row("SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if !matches!(
        marker,
        (43, 1, 42, 927)
            | (43, 1, 43, 946)
            | (44, 1, 43, 971)
            | (44, 1, 44, 990)
            | (45, 1, 44, 1016)
            | (45, 1, 45, 1035)
            | (46, 1, 45, 1062)
            | (46, 1, 46, 1081)
            | (47, 1, 46, 1109)
            | (47, 1, 47, 1128)
            | (48, 1, 47, 1157)
            | (48, 1, 48, 1176)
            | (49, 1, 48, 1206)
            | (49, 1, 49, 1225)
            | (50, 1, 49, 1256)
            | (50, 1, 50, 1275)
            | (51, 1, 50, 1307)
            | (51, 1, 51, 1326)
            | (52, 1, 51, 1359)
            | (52, 1, 52, 1378)
            | (53, 1, 52, 1412)
            | (53, 1, 53, 1431)
            | (54, 1, 53, 1466)
            | (54, 1, 54, 1485)
            | (55, 1, 54, 1521)
            | (55, 1, 55, 1540)
            | (56, 1, 55, 1577)
            | (56, 1, 56, 1596)
            | (57, 1, 56, 1634)
            | (57, 1, 57, 1653)
            | (58, 1, 57, 1692)
            | (58, 1, 58, 1711)
            | (59, 1, 58, 1751)
            | (59, 1, 59, 1770)
            | (60, 1, 59, 1811)
            | (60, 1, 60, 1830)
            | (61, 1, 60, 1872)
            | (61, 1, 61, 1891)
            | (62, 1, 61, 1934)
            | (62, 1, 62, 1953)
            | (63, 1, 62, 1997)
            | (63, 1, 63, 2016)
            | (64, 1, 63, 2061)
            | (64, 1, 64, 2080)
            | (65, 1, 64, 2126)
            | (65, 1, 65, 2145)
    ) {
        return Ok(false);
    }
    for table in [
        "taskrun_assignment_occupations",
        "taskrun_assignment_lease_renewals",
    ] {
        let expected = MIGRATION_V43
            .split(';')
            .map(str::trim)
            .find(|s| s.starts_with(&format!("CREATE TABLE {table} ")));
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()?;
        if expected.is_none_or(|expected| {
            actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(expected))
        }) {
            return Ok(false);
        }
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(table, operation);
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
    }
    if !v43_global_command_triggers_match(connection)? {
        return Ok(false);
    }
    if !v43_renewal_append_only_triggers_match(connection)? {
        return Ok(false);
    }
    let index: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='index' AND name='taskrun_assignment_occupations_capacity'", [], |r| r.get(0)).optional()?;
    if !index.as_ref().is_some_and(|sql| normalize_sql(sql)==normalize_sql("CREATE INDEX taskrun_assignment_occupations_capacity ON taskrun_assignment_occupations(node_id,state)")) {
        return Ok(false);
    }
    let occupation_sql = if version >= 57 {
        "SELECT COUNT(*) FROM taskrun_assignments a LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) LEFT JOIN taskrun_no_effect_release_receipts r USING(taskrun_id,fence) LEFT JOIN taskrun_terminal_settlement_receipts t USING(taskrun_id,fence) WHERE o.taskrun_id IS NULL OR o.attempt_id!=a.attempt_id OR o.node_id!=a.node_id OR o.node_epoch!=a.node_epoch OR (o.state='active' AND o.release_event_id IS NOT NULL) OR (o.state='released' AND (o.release_event_id IS NULL OR NOT ((r.command_id IS NOT NULL AND o.dispatch_intent='absent') OR (t.taskrun_id IS NOT NULL AND t.terminal_event_id=o.release_event_id AND o.dispatch_intent IN ('present','absent')) OR EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts u JOIN events e ON e.event_id=u.occupation_release_event_id WHERE u.predecessor_taskrun_id=o.taskrun_id AND u.occupation_fence=o.fence AND u.predecessor_attempt_id=o.attempt_id AND u.occupation_release_reason='user_supersession' AND u.occupation_release_event_id=o.release_event_id AND u.occupation_release_version=e.sequence AND e.aggregate_type=1 AND e.aggregate_id=o.taskrun_id)))) OR o.state NOT IN ('active','released')"
    } else if version >= 49 {
        "SELECT COUNT(*) FROM taskrun_assignments a LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) LEFT JOIN taskrun_no_effect_release_receipts r USING(taskrun_id,fence) LEFT JOIN taskrun_terminal_settlement_receipts t USING(taskrun_id,fence) WHERE o.taskrun_id IS NULL OR o.attempt_id!=a.attempt_id OR o.node_id!=a.node_id OR o.node_epoch!=a.node_epoch OR (o.state='active' AND o.release_event_id IS NOT NULL) OR (o.state='released' AND (o.release_event_id IS NULL OR NOT ((r.command_id IS NOT NULL AND o.dispatch_intent='absent') OR (t.taskrun_id IS NOT NULL AND t.terminal_event_id=o.release_event_id AND o.dispatch_intent IN ('present','absent'))))) OR o.state NOT IN ('active','released')"
    } else if version >= 45 {
        "SELECT COUNT(*) FROM taskrun_assignments a LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) LEFT JOIN taskrun_no_effect_release_receipts r USING(taskrun_id,fence) WHERE o.taskrun_id IS NULL OR o.attempt_id!=a.attempt_id OR o.node_id!=a.node_id OR o.node_epoch!=a.node_epoch OR (o.state='active' AND o.release_event_id IS NOT NULL) OR (o.state='released' AND (o.release_event_id IS NULL OR r.command_id IS NULL OR o.dispatch_intent!='absent')) OR o.state NOT IN ('active','released')"
    } else {
        "SELECT COUNT(*) FROM taskrun_assignments a LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) WHERE o.taskrun_id IS NULL OR o.attempt_id!=a.attempt_id OR o.node_id!=a.node_id OR o.node_epoch!=a.node_epoch OR o.state!='active' OR o.release_event_id IS NOT NULL"
    };
    let inconsistent_occupations: i64 = connection.query_row(occupation_sql, [], |r| r.get(0))?;
    let orphan_occupations: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_assignment_occupations o LEFT JOIN taskrun_assignments a USING(taskrun_id,fence) WHERE a.taskrun_id IS NULL",
        [], |r| r.get(0),
    )?;
    let inconsistent_renewals: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_assignment_lease_renewals r LEFT JOIN taskrun_assignments a USING(taskrun_id,fence) WHERE a.taskrun_id IS NULL OR r.attempt_id!=a.attempt_id OR r.node_id!=a.node_id OR r.node_epoch!=a.node_epoch OR r.lease_expires_at_ms<a.lease_expires_at_ms",
        [], |r| r.get(0),
    )?;
    let colliding_renewal_ids: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_assignment_lease_renewals r WHERE EXISTS(SELECT 1 FROM command_receipts c WHERE c.command_id=r.renewal_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts p WHERE p.command_id=r.renewal_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts t WHERE t.command_id=r.renewal_id)",
        [], |r| r.get(0),
    )?;
    let inconsistent_expiries: i64 = connection.query_row(
        "SELECT COUNT(*) FROM taskrun_assignments a JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) WHERE o.lease_expires_at_ms!=MAX(a.lease_expires_at_ms,COALESCE((SELECT MAX(r.lease_expires_at_ms) FROM taskrun_assignment_lease_renewals r WHERE r.taskrun_id=a.taskrun_id AND r.fence=a.fence),a.lease_expires_at_ms))",
        [], |r| r.get(0),
    )?;
    Ok(inconsistent_occupations == 0
        && orphan_occupations == 0
        && inconsistent_renewals == 0
        && colliding_renewal_ids == 0
        && inconsistent_expiries == 0)
}

fn v43_renewal_append_only_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in [
        (
            "taskrun_assignment_lease_renewals_immutable",
            "CREATE TRIGGER taskrun_assignment_lease_renewals_immutable BEFORE UPDATE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
        ),
        (
            "taskrun_assignment_lease_renewals_no_delete",
            "CREATE TRIGGER taskrun_assignment_lease_renewals_no_delete BEFORE DELETE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v43_global_command_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in [
        (
            "global_command_id_from_lease_renewals_v43",
            "CREATE TRIGGER global_command_id_from_lease_renewals_v43 BEFORE INSERT ON taskrun_assignment_lease_renewals WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.renewal_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.renewal_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.renewal_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_command_receipts_v43",
            "CREATE TRIGGER global_command_id_from_command_receipts_v43 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_project_workspace_receipts_v43",
            "CREATE TRIGGER global_command_id_from_project_workspace_receipts_v43 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_taskrun_claim_receipts_v43",
            "CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v43 BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}
