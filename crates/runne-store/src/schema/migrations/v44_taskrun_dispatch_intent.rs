pub(super) const MIGRATION_V44: &str = r#"
CREATE TABLE taskrun_dispatch_intents (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16), fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL UNIQUE CHECK(length(attempt_id)=16), node_id BLOB NOT NULL CHECK(length(node_id)=16),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0), state TEXT NOT NULL CHECK(state IN ('present','unknown')),
 PRIMARY KEY(taskrun_id,fence), FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignment_occupations(taskrun_id,fence)
);
CREATE TRIGGER taskrun_dispatch_intents_immutable BEFORE UPDATE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END;
CREATE TRIGGER taskrun_dispatch_intents_no_delete BEFORE DELETE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END;
CREATE TRIGGER taskrun_occupation_intent_guard BEFORE UPDATE OF dispatch_intent ON taskrun_assignment_occupations
WHEN (NEW.dispatch_intent='present' AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=NEW.taskrun_id AND i.fence=NEW.fence AND i.attempt_id=NEW.attempt_id AND i.node_id=NEW.node_id AND i.node_epoch=NEW.node_epoch AND i.state='present'))
 OR (OLD.dispatch_intent IN ('present','unknown') AND NEW.dispatch_intent!=OLD.dispatch_intent)
BEGIN SELECT RAISE(ABORT,'dispatch intent evidence mismatch'); END;
INSERT INTO taskrun_dispatch_intents(taskrun_id,fence,attempt_id,node_id,node_epoch,state)
 SELECT taskrun_id,fence,attempt_id,node_id,node_epoch,dispatch_intent FROM taskrun_assignment_occupations WHERE dispatch_intent IN ('present','unknown');
"#;

pub(super) fn apply_v44_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V44)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(44)", [])?;
    tx.commit()
}

pub(super) fn v44_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 44..=47) { return Ok(false); }
    if !v43_matches(connection, version)? { return Ok(false); }
    let marker: (i64,i64,i64,i64) = connection.query_row("SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if !matches!(marker,(44,1,43,971) | (44,1,44,990) | (45,1,44,1016) | (45,1,45,1035) | (46,1,45,1062) | (46,1,46,1081) | (47,1,46,1109) | (47,1,47,1128)) { return Ok(false); }
    let expected = MIGRATION_V44.split(';').map(str::trim).find(|s| s.starts_with("CREATE TABLE taskrun_dispatch_intents ")).unwrap();
    let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_dispatch_intents'", [], |r| r.get(0)).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql)!=normalize_ddl(expected)) { return Ok(false); }
    for (name, sql) in [
        ("taskrun_dispatch_intents_immutable", "CREATE TRIGGER taskrun_dispatch_intents_immutable BEFORE UPDATE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
        ("taskrun_dispatch_intents_no_delete", "CREATE TRIGGER taskrun_dispatch_intents_no_delete BEFORE DELETE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
        ("taskrun_occupation_intent_guard", "CREATE TRIGGER taskrun_occupation_intent_guard BEFORE UPDATE OF dispatch_intent ON taskrun_assignment_occupations WHEN (NEW.dispatch_intent='present' AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=NEW.taskrun_id AND i.fence=NEW.fence AND i.attempt_id=NEW.attempt_id AND i.node_id=NEW.node_id AND i.node_epoch=NEW.node_epoch AND i.state='present')) OR (OLD.dispatch_intent IN ('present','unknown') AND NEW.dispatch_intent!=OLD.dispatch_intent) BEGIN SELECT RAISE(ABORT,'dispatch intent evidence mismatch'); END"),
    ] {
        let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1", [name], |r| r.get(0)).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual)!=normalize_sql(sql)) { return Ok(false); }
    }
    let mismatch: i64 = connection.query_row("SELECT COUNT(*) FROM taskrun_assignment_occupations o LEFT JOIN taskrun_dispatch_intents i USING(taskrun_id,fence) WHERE (o.dispatch_intent='absent' AND i.taskrun_id IS NOT NULL) OR (o.dispatch_intent IN ('present','unknown') AND (i.taskrun_id IS NULL OR i.attempt_id!=o.attempt_id OR i.node_id!=o.node_id OR i.node_epoch!=o.node_epoch OR i.state!=o.dispatch_intent))", [], |r| r.get(0))?;
    let orphan: i64 = connection.query_row("SELECT COUNT(*) FROM taskrun_dispatch_intents i LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) WHERE o.taskrun_id IS NULL", [], |r| r.get(0))?;
    Ok(mismatch==0 && orphan==0)
}
