pub(super) const MIGRATION_V55: &str = r#"
CREATE TABLE provider_remote_terminal_artifacts (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
 profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 128),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32 AND semantic_digest!=zeroblob(32)),
 prepared_digest BLOB NOT NULL CHECK(length(prepared_digest)=32 AND prepared_digest!=zeroblob(32)),
 credential_realm TEXT NOT NULL CHECK(length(credential_realm) BETWEEN 1 AND 128),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 response_id_digest BLOB NOT NULL CHECK(length(response_id_digest)=32 AND response_id_digest!=zeroblob(32)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 key_id BLOB NOT NULL CHECK(length(key_id)=16 AND key_id!=zeroblob(16)),
 key_version INTEGER NOT NULL CHECK(key_version>0),
 nonce BLOB NOT NULL CHECK(length(nonce)=12 AND nonce!=zeroblob(12)),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 17 AND 131088),
 plaintext_len INTEGER NOT NULL CHECK(1<=plaintext_len AND plaintext_len<=131072),
 plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32 AND plaintext_digest!=zeroblob(32)),
 disposition INTEGER NOT NULL CHECK(disposition IN (1,2,3,5)),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_response_bindings(dispatch_attempt_id),
 FOREIGN KEY(key_id,key_version,nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce)
);
CREATE TRIGGER provider_remote_terminal_artifacts_immutable BEFORE UPDATE ON provider_remote_terminal_artifacts BEGIN SELECT RAISE(ABORT,'Provider remote terminal artifact is append only'); END;
CREATE TRIGGER provider_remote_terminal_artifacts_no_delete BEFORE DELETE ON provider_remote_terminal_artifacts BEGIN SELECT RAISE(ABORT,'Provider remote terminal artifact is append only'); END;
"#;

const V55_DISPOSITION_DDL: &str = "CREATE TABLE provider_terminal_dispositions ( dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16), disposition INTEGER NOT NULL CHECK(disposition IN (1,2,3,4,5,6)), FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_accounting_settlements(dispatch_attempt_id) )";

pub(super) fn apply_v55_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(
        "DROP TRIGGER provider_terminal_dispositions_immutable;
         DROP TRIGGER provider_terminal_dispositions_no_delete;
         DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_insert;
         DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_update;
         DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_delete;
         ALTER TABLE provider_terminal_dispositions RENAME TO provider_terminal_dispositions_v50;",
    )?;
    tx.execute_batch(V55_DISPOSITION_DDL)?;
    tx.execute_batch("INSERT INTO provider_terminal_dispositions SELECT dispatch_attempt_id,disposition FROM provider_terminal_dispositions_v50; DROP TABLE provider_terminal_dispositions_v50;")?;
    tx.execute_batch(MIGRATION_V55)?;
    tx.execute_batch("CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;
        CREATE TRIGGER provider_terminal_dispositions_no_delete BEFORE DELETE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END;")?;
    for table in [
        "provider_terminal_dispositions",
        "provider_remote_terminal_artifacts",
    ] {
        for operation in ["insert", "update", "delete"] {
            tx.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(55)", [])?;
    tx.commit()
}

pub(super) fn v55_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 55..=69) {
        return Ok(false);
    }
    if !v54_matches(connection, version)? {
        return Ok(false);
    }
    if !table_sql_matches_migration(
        connection,
        "provider_remote_terminal_artifacts",
        MIGRATION_V55,
    )? {
        return Ok(false);
    }
    if !v55_disposition_objects_match(connection)? {
        return Ok(false);
    }
    for (name, expected) in V55_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for table in [
        "provider_remote_terminal_artifacts",
        "provider_terminal_dispositions",
    ] {
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(table, operation);
            if !schema_trigger_matches(connection, &name, &expected)? {
                return Ok(false);
            }
        }
    }
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_terminal_artifacts t
         LEFT JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
         LEFT JOIN provider_execution_admissions a USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=t.dispatch_attempt_id
         LEFT JOIN provider_terminal_dispositions disposition ON disposition.dispatch_attempt_id=t.dispatch_attempt_id
         LEFT JOIN provider_journal_key_refs k ON k.key_id=t.key_id AND k.key_version=t.key_version
         LEFT JOIN provider_encryption_nonces n ON n.key_id=t.key_id AND n.key_version=t.key_version
           AND n.nonce=t.nonce AND n.dispatch_attempt_id=t.dispatch_attempt_id
         WHERE q.dispatch_attempt_id IS NULL OR r.dispatch_attempt_id IS NULL
           OR a.dispatch_attempt_id IS NULL OR d.attempt_id IS NULL
           OR (disposition.dispatch_attempt_id IS NOT NULL AND disposition.disposition NOT IN (4,6)
               AND disposition.disposition!=t.disposition)
           OR t.taskrun_id!=q.taskrun_id OR t.taskrun_attempt_id!=q.taskrun_attempt_id
           OR t.provider_id!=q.provider_id OR t.profile_id!=q.profile_id
           OR t.profile_digest!=q.profile_digest OR t.pricing_revision_digest!=q.pricing_revision_digest
           OR t.semantic_digest!=q.semantic_digest OR t.prepared_digest!=q.prepared_digest
           OR t.credential_realm!=q.credential_realm OR t.request_digest!=q.request_digest
           OR t.runtime_authority_id!=q.runtime_authority_id
           OR t.database_generation!=q.database_generation OR t.runtime_generation!=q.runtime_generation
           OR t.fencing_token!=q.fencing_token OR t.key_id!=q.key_id OR t.key_version!=q.key_version
           OR r.taskrun_id!=t.taskrun_id OR r.taskrun_attempt_id!=t.taskrun_attempt_id
           OR r.provider_id!=t.provider_id OR r.profile_id!=t.profile_id
           OR r.profile_digest!=t.profile_digest OR r.pricing_revision_digest!=t.pricing_revision_digest
           OR r.credential_realm!=t.credential_realm
           OR r.request_digest!=t.request_digest OR r.key_id!=t.key_id OR r.key_version!=t.key_version
           OR r.plaintext_digest!=t.response_id_digest
           OR k.key_id IS NULL OR k.runtime_authority_id!=t.runtime_authority_id
           OR k.database_generation!=t.database_generation OR n.nonce IS NULL
           OR n.purpose!=2 OR n.sequence IS NOT NULL OR length(t.ciphertext)!=t.plaintext_len+16
           OR d.profile_digest!=t.profile_digest",
        [], |row| row.get(0),
    )?;
    if invalid != 0 {
        return Ok(false);
    }
    Ok(true)
}

fn schema_trigger_matches(
    connection: &Connection,
    name: &str,
    expected: &str,
) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|sql| normalize_sql(&sql) == normalize_sql(expected)))
}

const V55_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_remote_terminal_artifacts_immutable",
        "CREATE TRIGGER provider_remote_terminal_artifacts_immutable BEFORE UPDATE ON provider_remote_terminal_artifacts BEGIN SELECT RAISE(ABORT,'Provider remote terminal artifact is append only'); END",
    ),
    (
        "provider_remote_terminal_artifacts_no_delete",
        "CREATE TRIGGER provider_remote_terminal_artifacts_no_delete BEFORE DELETE ON provider_remote_terminal_artifacts BEGIN SELECT RAISE(ABORT,'Provider remote terminal artifact is append only'); END",
    ),
];
const V55_DISPOSITION_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_terminal_dispositions_immutable",
        "CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END",
    ),
    (
        "provider_terminal_dispositions_no_delete",
        "CREATE TRIGGER provider_terminal_dispositions_no_delete BEFORE DELETE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END",
    ),
];

pub(super) fn v55_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_terminal_artifacts");
    triggers.extend_from_slice(V55_TRIGGERS);
    triggers.extend_from_slice(V55_FENCE_TRIGGERS);
}

const V55_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_terminal_artifacts_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_artifacts_insert\" AFTER INSERT ON \"provider_remote_terminal_artifacts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_artifacts_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_artifacts_update\" AFTER UPDATE ON \"provider_remote_terminal_artifacts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_terminal_artifacts_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_terminal_artifacts_delete\" AFTER DELETE ON \"provider_remote_terminal_artifacts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];
