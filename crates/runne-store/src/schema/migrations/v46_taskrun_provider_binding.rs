pub(super) const MIGRATION_V46: &str = r#"
CREATE TABLE taskrun_provider_bindings (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 fence INTEGER NOT NULL CHECK(fence>0),
 attempt_id BLOB NOT NULL UNIQUE CHECK(length(attempt_id)=16),
 node_id BLOB NOT NULL CHECK(length(node_id)=16),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 claim_version INTEGER NOT NULL CHECK(claim_version>0),
 call_id BLOB NOT NULL UNIQUE CHECK(length(call_id)=16),
 call_digest_version INTEGER NOT NULL CHECK(call_digest_version IN (1,2)),
 prepared_digest BLOB NOT NULL CHECK(length(prepared_digest)=32),
 render_digest BLOB NOT NULL CHECK(length(render_digest)=32),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32),
 provider_idempotency_key TEXT NOT NULL UNIQUE CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
 PRIMARY KEY(taskrun_id,fence),
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_dispatch_intents(taskrun_id,fence),
 FOREIGN KEY(call_id) REFERENCES provider_prepared_requests(call_id)
);
CREATE TRIGGER taskrun_provider_bindings_immutable BEFORE UPDATE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END;
CREATE TRIGGER taskrun_provider_bindings_no_delete BEFORE DELETE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END;
"#;

pub(super) fn apply_v46_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V46)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(46)", [])?;
    tx.commit()
}

pub(super) fn v46_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 46 | 47 | 48) || !v45_matches(connection, version)? {
        return Ok(false);
    }
    let marker: (i64,i64,i64,i64) = connection.query_row("SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if !matches!(marker,(46,1,45,1062) | (46,1,46,1081) | (47,1,46,1109) | (47,1,47,1128) | (48,1,47,1157) | (48,1,48,1176)) {
        return Ok(false);
    }
    let expected = MIGRATION_V46.split(';').map(str::trim).find(|s| s.starts_with("CREATE TABLE taskrun_provider_bindings ")).unwrap();
    let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='taskrun_provider_bindings'", [], |r| r.get(0)).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql)!=normalize_ddl(expected)) { return Ok(false); }
    for (name,sql) in [
        ("taskrun_provider_bindings_immutable", "CREATE TRIGGER taskrun_provider_bindings_immutable BEFORE UPDATE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
        ("taskrun_provider_bindings_no_delete", "CREATE TRIGGER taskrun_provider_bindings_no_delete BEFORE DELETE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
    ] {
        let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1", [name], |r| r.get(0)).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual)!=normalize_sql(sql)) { return Ok(false); }
    }
    let invalid: i64 = connection.query_row("SELECT COUNT(*) FROM taskrun_provider_bindings b LEFT JOIN taskrun_dispatch_intents i USING(taskrun_id,fence) LEFT JOIN taskrun_assignment_occupations o USING(taskrun_id,fence) LEFT JOIN taskrun_claim_receipts c USING(taskrun_id,fence) LEFT JOIN provider_prepared_requests p USING(call_id) LEFT JOIN provider_execution_admissions a ON a.call_id=b.call_id AND a.provider_idempotency_key=b.provider_idempotency_key LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id WHERE i.taskrun_id IS NULL OR i.state!='present' OR o.taskrun_id IS NULL OR o.state!='active' OR o.dispatch_intent!='present' OR o.attempt_id!=b.attempt_id OR o.node_id!=b.node_id OR o.node_epoch!=b.node_epoch OR c.taskrun_id IS NULL OR c.new_version!=b.claim_version OR p.call_id IS NULL OR p.call_digest_version!=b.call_digest_version OR p.prepared_digest!=b.prepared_digest OR p.render_digest!=b.render_digest OR p.profile_digest!=b.profile_digest OR a.call_id IS NULL OR a.taskrun_id!=b.taskrun_id OR a.execution_attempt_id!=b.attempt_id OR a.prepared_digest!=b.prepared_digest OR a.render_digest!=b.render_digest OR a.profile_digest!=b.profile_digest OR d.attempt_id IS NULL OR d.call_id!=b.call_id OR d.provider_idempotency_key!=b.provider_idempotency_key OR d.prepared_digest!=b.prepared_digest OR d.render_digest!=b.render_digest OR d.profile_digest!=b.profile_digest", [], |r| r.get(0))?;
    Ok(invalid==0)
}
