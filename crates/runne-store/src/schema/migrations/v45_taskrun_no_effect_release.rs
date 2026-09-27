pub(super) const MIGRATION_V45: &str = r#"
CREATE TABLE taskrun_no_effect_release_receipts (
 command_id BLOB PRIMARY KEY CHECK(length(command_id)=16),
 idempotency_scope BLOB NOT NULL,
 idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
 fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 fence INTEGER NOT NULL CHECK(fence>0),
 failure_event_id BLOB NOT NULL UNIQUE CHECK(length(failure_event_id)=16),
 new_version INTEGER NOT NULL CHECK(new_version>0),
 UNIQUE(idempotency_scope,idempotency_key),
 UNIQUE(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignment_occupations(taskrun_id,fence),
 FOREIGN KEY(failure_event_id) REFERENCES events(event_id)
);
CREATE TRIGGER taskrun_no_effect_release_immutable BEFORE UPDATE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END;
CREATE TRIGGER taskrun_no_effect_release_no_delete BEFORE DELETE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END;
CREATE TRIGGER global_command_id_from_release_v45 BEFORE INSERT ON taskrun_no_effect_release_receipts
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT,'global command id collision'); END;
CREATE TRIGGER global_command_id_from_command_receipts_v45 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END;
CREATE TRIGGER global_command_id_from_project_workspace_receipts_v45 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END;
CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v45 BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END;
CREATE TRIGGER global_command_id_from_lease_renewals_v45 BEFORE INSERT ON taskrun_assignment_lease_renewals WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.renewal_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END;
"#;

pub(super) fn apply_v45_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V45)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(45)", [])?;
    tx.commit()
}

pub(super) fn v45_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 45..=47) || !v44_matches(connection, version)? { return Ok(false); }
    let marker: (i64,i64,i64,i64) = connection.query_row("SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if !matches!(marker,(45,1,44,1016) | (45,1,45,1035) | (46,1,45,1062) | (46,1,46,1081) | (47,1,46,1109) | (47,1,47,1128)) { return Ok(false); }
    let expected = MIGRATION_V45.split(';').map(str::trim).find(|s| s.starts_with("CREATE TABLE taskrun_no_effect_release_receipts ")).unwrap();
    let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_no_effect_release_receipts'", [], |r| r.get(0)).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql)!=normalize_ddl(expected)) { return Ok(false); }
    for (name, sql) in [
        ("taskrun_no_effect_release_immutable", "CREATE TRIGGER taskrun_no_effect_release_immutable BEFORE UPDATE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
        ("taskrun_no_effect_release_no_delete", "CREATE TRIGGER taskrun_no_effect_release_no_delete BEFORE DELETE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
        ("global_command_id_from_release_v45", "CREATE TRIGGER global_command_id_from_release_v45 BEFORE INSERT ON taskrun_no_effect_release_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ("global_command_id_from_command_receipts_v45", "CREATE TRIGGER global_command_id_from_command_receipts_v45 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ("global_command_id_from_project_workspace_receipts_v45", "CREATE TRIGGER global_command_id_from_project_workspace_receipts_v45 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ("global_command_id_from_taskrun_claim_receipts_v45", "CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v45 BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ("global_command_id_from_lease_renewals_v45", "CREATE TRIGGER global_command_id_from_lease_renewals_v45 BEFORE INSERT ON taskrun_assignment_lease_renewals WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.renewal_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
    ] {
        let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1", [name], |r| r.get(0)).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual)!=normalize_sql(sql)) { return Ok(false); }
    }
    let invalid: i64 = connection.query_row("SELECT (SELECT COUNT(*) FROM taskrun_no_effect_release_receipts r LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) LEFT JOIN events e ON e.event_id=r.failure_event_id WHERE o.taskrun_id IS NULL OR e.event_id IS NULL OR o.state!='released' OR o.release_event_id!=r.failure_event_id OR o.dispatch_intent!='absent' OR o.attempt_id!=r.attempt_id OR e.aggregate_type!=1 OR e.aggregate_id!=r.taskrun_id OR e.sequence!=r.new_version OR e.command_id!=r.command_id OR e.causation_id IS NULL) + (SELECT COUNT(*) FROM taskrun_assignment_occupations o LEFT JOIN taskrun_no_effect_release_receipts r USING(taskrun_id,fence) LEFT JOIN taskrun_dispatch_intents i USING(taskrun_id,fence) WHERE o.state='released' AND (r.command_id IS NULL OR i.taskrun_id IS NOT NULL))", [], |r| r.get(0))?;
    let collisions: i64 = connection.query_row("SELECT COUNT(*) FROM taskrun_no_effect_release_receipts r WHERE EXISTS(SELECT 1 FROM command_receipts c WHERE c.command_id=r.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts p WHERE p.command_id=r.command_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts c WHERE c.command_id=r.command_id) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals l WHERE l.renewal_id=r.command_id)", [], |r| r.get(0))?;
    Ok(invalid==0 && collisions==0 && released_streams_match(connection)?)
}

fn released_streams_match(connection: &Connection) -> SqliteResult<bool> {
    use runne_application::ports::{ExecutionNodeId, TaskRunClaimReceipt, TaskRunFence};
    use runne_domain::id::{AttemptId, CommandId, EventId, TaskRunId};
    use runne_domain::timestamp::Timestamp;

    let mut statement = connection.prepare(
        "SELECT r.taskrun_id,r.attempt_id,r.fence,r.command_id,r.idempotency_key,r.failure_event_id,r.new_version,c.command_id,c.idempotency_key,c.lease_expires_at_ms,c.new_version,c.admitted_event_id,c.started_event_id,o.node_id,o.node_epoch FROM taskrun_no_effect_release_receipts r JOIN taskrun_claim_receipts c USING(taskrun_id,fence) JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) ORDER BY r.taskrun_id,r.fence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?,
            row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?, row.get::<_, Vec<u8>>(7)?, row.get::<_, Vec<u8>>(8)?,
            row.get::<_, i64>(9)?, row.get::<_, i64>(10)?, row.get::<_, Vec<u8>>(11)?,
            row.get::<_, Vec<u8>>(12)?, row.get::<_, Vec<u8>>(13)?, row.get::<_, i64>(14)?,
        ))
    })?;
    for row in rows {
        let (task, attempt, fence, release_command, release_key, release_event, release_version,
            claim_command, claim_key, lease_ms, claim_version, admitted, started, node, epoch) = row?;
        let Ok(task_bytes) = <[u8; 16]>::try_from(task) else { return Ok(false) };
        let Ok(attempt_bytes) = <[u8; 16]>::try_from(attempt) else { return Ok(false) };
        let Ok(node_bytes) = <[u8; 16]>::try_from(node) else { return Ok(false) };
        let Ok(admitted_bytes) = <[u8; 16]>::try_from(admitted) else { return Ok(false) };
        let Ok(started_bytes) = <[u8; 16]>::try_from(started) else { return Ok(false) };
        let Ok(claim_id_bytes) = <[u8; 16]>::try_from(claim_command) else { return Ok(false) };
        let Ok(claim_key) = String::from_utf8(claim_key) else { return Ok(false) };
        let Ok(claim_key) = runne_domain::id::IdempotencyKey::new(claim_key) else { return Ok(false) };
        let claim_receipt = TaskRunClaimReceipt {
            taskrun_id: TaskRunId::from_bytes(task_bytes),
            attempt_id: AttemptId::from_bytes(attempt_bytes),
            node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node_bytes).to_string()),
            node_epoch: u64::try_from(epoch).unwrap_or(0),
            fence: TaskRunFence(u64::try_from(fence).unwrap_or(0)),
            lease_expires_at: Timestamp::from_unix_micros(lease_ms.saturating_mul(1000)),
            new_version: u64::try_from(claim_version).unwrap_or(0),
            admitted_event_id: EventId::from_bytes(admitted_bytes),
            started_event_id: EventId::from_bytes(started_bytes),
        };
        let Ok(release_command) = <[u8; 16]>::try_from(release_command) else { return Ok(false) };
        let Ok(release_event) = <[u8; 16]>::try_from(release_event) else { return Ok(false) };
        if crate::store::taskrun_claim::verify_released_stream(
            connection,
            &claim_receipt,
            CommandId::from_bytes(claim_id_bytes),
            claim_key.as_str().as_bytes(),
            EventId::from_bytes(release_event),
            u64::try_from(release_version).unwrap_or(0),
            crate::store::taskrun_claim::ReleaseEventMetadata {
                command_id: CommandId::from_bytes(release_command),
                idempotency_key: &release_key,
            },
        ).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}
