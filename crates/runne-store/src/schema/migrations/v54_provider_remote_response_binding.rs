pub(super) const MIGRATION_V54: &str = r#"
CREATE TABLE provider_remote_request_intents (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
 profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 128),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 credential_realm TEXT NOT NULL CHECK(length(credential_realm) BETWEEN 1 AND 128),
 semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32 AND semantic_digest!=zeroblob(32)),
 prepared_digest BLOB NOT NULL CHECK(length(prepared_digest)=32 AND prepared_digest!=zeroblob(32)),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 key_id BLOB NOT NULL CHECK(length(key_id)=16 AND key_id!=zeroblob(16)),
 key_version INTEGER NOT NULL CHECK(key_version>0),
 nonce BLOB NOT NULL CHECK(length(nonce)=12 AND nonce!=zeroblob(12)),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 17 AND 524304),
 plaintext_len INTEGER NOT NULL CHECK(plaintext_len BETWEEN 1 AND 524288),
 plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32 AND plaintext_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_dispatch_attempts(attempt_id),
 FOREIGN KEY(key_id,key_version,nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce)
);
CREATE TRIGGER provider_remote_request_intents_immutable BEFORE UPDATE ON provider_remote_request_intents BEGIN SELECT RAISE(ABORT,'Provider remote request intent is append only'); END;
CREATE TRIGGER provider_remote_request_intents_no_delete BEFORE DELETE ON provider_remote_request_intents BEGIN SELECT RAISE(ABORT,'Provider remote request intent is append only'); END;
CREATE TABLE provider_remote_response_bindings (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
 profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 128),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 credential_realm TEXT NOT NULL CHECK(length(credential_realm) BETWEEN 1 AND 128),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 key_id BLOB NOT NULL CHECK(length(key_id)=16 AND key_id!=zeroblob(16)),
 key_version INTEGER NOT NULL CHECK(key_version>0),
 nonce BLOB NOT NULL CHECK(length(nonce)=12 AND nonce!=zeroblob(12)),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 17 AND 272),
 plaintext_len INTEGER NOT NULL CHECK(plaintext_len BETWEEN 1 AND 256),
 plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32 AND plaintext_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL,
 UNIQUE(taskrun_id,taskrun_attempt_id,dispatch_attempt_id),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_request_intents(dispatch_attempt_id),
 FOREIGN KEY(key_id,key_version,nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce)
);
CREATE TRIGGER provider_remote_response_bindings_immutable BEFORE UPDATE ON provider_remote_response_bindings BEGIN SELECT RAISE(ABORT,'Provider remote response identity is append only'); END;
CREATE TRIGGER provider_remote_response_bindings_no_delete BEFORE DELETE ON provider_remote_response_bindings BEGIN SELECT RAISE(ABORT,'Provider remote response identity is append only'); END;
"#;

const V54_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_remote_request_intents_immutable",
        "CREATE TRIGGER provider_remote_request_intents_immutable BEFORE UPDATE ON provider_remote_request_intents BEGIN SELECT RAISE(ABORT,'Provider remote request intent is append only'); END",
    ),
    (
        "provider_remote_request_intents_no_delete",
        "CREATE TRIGGER provider_remote_request_intents_no_delete BEFORE DELETE ON provider_remote_request_intents BEGIN SELECT RAISE(ABORT,'Provider remote request intent is append only'); END",
    ),
    (
        "provider_remote_response_bindings_immutable",
        "CREATE TRIGGER provider_remote_response_bindings_immutable BEFORE UPDATE ON provider_remote_response_bindings BEGIN SELECT RAISE(ABORT,'Provider remote response identity is append only'); END",
    ),
    (
        "provider_remote_response_bindings_no_delete",
        "CREATE TRIGGER provider_remote_response_bindings_no_delete BEFORE DELETE ON provider_remote_response_bindings BEGIN SELECT RAISE(ABORT,'Provider remote response identity is append only'); END",
    ),
];

pub(super) fn apply_v54_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V54)?;
    for table in [
        "provider_remote_request_intents",
        "provider_remote_response_bindings",
    ] {
        for operation in ["insert", "update", "delete"] {
            tx.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(54)", [])?;
    tx.commit()
}

pub(super) fn v54_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 54..=69) {
        return Ok(false);
    }
    if !v53_base_matches(connection, version)? {
        return Ok(false);
    }
    for table in [
        "provider_remote_request_intents",
        "provider_remote_response_bindings",
    ] {
        if !table_sql_matches_migration(connection, table, MIGRATION_V54)? {
            return Ok(false);
        }
    }
    for (name, expected) in V54_TRIGGERS {
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
    for table in [
        "provider_remote_request_intents",
        "provider_remote_response_bindings",
    ] {
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(table, operation);
            let actual: Option<String> = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [&name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual.is_none_or(|sql| normalize_sql(&sql) != normalize_sql(&expected)) {
                return Ok(false);
            }
        }
    }
    let invalid_intents: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_request_intents r
         LEFT JOIN provider_execution_admissions a USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=r.dispatch_attempt_id
         LEFT JOIN provider_effect_starts e ON e.dispatch_attempt_id=r.dispatch_attempt_id
         LEFT JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
         LEFT JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
         LEFT JOIN provider_secondary_profile_attempts s USING(dispatch_attempt_id)
         LEFT JOIN provider_secondary_profile_grants g ON g.grant_id=s.grant_id
         LEFT JOIN provider_journal_key_refs k ON k.key_id=r.key_id AND k.key_version=r.key_version
         LEFT JOIN provider_encryption_nonces n ON n.key_id=r.key_id AND n.key_version=r.key_version
           AND n.nonce=r.nonce AND n.dispatch_attempt_id=r.dispatch_attempt_id
         WHERE a.dispatch_attempt_id IS NULL OR d.attempt_id IS NULL OR e.dispatch_attempt_id IS NULL
           OR p.dispatch_attempt_id IS NULL OR c.dispatch_attempt_id IS NULL
           OR k.key_id IS NULL OR k.runtime_authority_id!=r.runtime_authority_id
           OR k.database_generation!=r.database_generation OR n.nonce IS NULL
           OR n.purpose!=2 OR n.sequence IS NOT NULL
           OR r.taskrun_id!=a.taskrun_id OR r.taskrun_attempt_id!=a.execution_attempt_id
           OR r.runtime_authority_id!=a.runtime_authority_id OR r.database_generation!=a.database_generation
           OR r.runtime_generation!=a.generation OR r.fencing_token!=a.fencing_token
           OR r.semantic_digest!=a.semantic_digest OR r.prepared_digest!=a.prepared_digest
           OR r.request_digest!=a.render_digest OR r.profile_digest!=a.profile_digest
           OR r.plaintext_digest!=r.request_digest
           OR r.pricing_revision_digest!=a.pricing_revision_digest
           OR r.provider_id!=p.provider_id OR r.credential_realm!=c.provider_id
           OR (s.dispatch_attempt_id IS NOT NULL AND (g.grant_id IS NULL
               OR r.provider_id!=g.provider_id OR r.profile_id!=g.profile_id
               OR r.profile_digest!=g.profile_digest
               OR r.pricing_revision_digest!=g.pricing_revision_digest))
           OR length(r.ciphertext)!=r.plaintext_len+16",
        [], |row| row.get(0),
    )?;
    if invalid_intents != 0 {
        return Ok(false);
    }
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_response_bindings r
         LEFT JOIN provider_execution_admissions a USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=r.dispatch_attempt_id
         LEFT JOIN provider_effect_starts e ON e.dispatch_attempt_id=r.dispatch_attempt_id
         LEFT JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
         LEFT JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
         LEFT JOIN provider_secondary_profile_attempts s USING(dispatch_attempt_id)
         LEFT JOIN provider_secondary_profile_grants g ON g.grant_id=s.grant_id
         LEFT JOIN provider_journal_key_refs k ON k.key_id=r.key_id AND k.key_version=r.key_version
         LEFT JOIN provider_encryption_nonces n ON n.key_id=r.key_id AND n.key_version=r.key_version
           AND n.nonce=r.nonce AND n.dispatch_attempt_id=r.dispatch_attempt_id
         LEFT JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
         WHERE a.dispatch_attempt_id IS NULL OR d.attempt_id IS NULL
           OR e.dispatch_attempt_id IS NULL OR p.dispatch_attempt_id IS NULL
           OR c.dispatch_attempt_id IS NULL
           OR q.dispatch_attempt_id IS NULL OR q.taskrun_id!=r.taskrun_id
           OR q.taskrun_attempt_id!=r.taskrun_attempt_id OR q.provider_id!=r.provider_id
           OR q.profile_id!=r.profile_id OR q.profile_digest!=r.profile_digest
           OR q.pricing_revision_digest!=r.pricing_revision_digest
           OR q.request_digest!=r.request_digest
           OR q.key_id!=r.key_id OR q.key_version!=r.key_version
           OR k.key_id IS NULL OR k.runtime_authority_id!=r.runtime_authority_id
           OR k.database_generation!=r.database_generation
           OR n.nonce IS NULL OR n.purpose!=2 OR n.sequence IS NOT NULL
           OR r.taskrun_id!=a.taskrun_id OR r.taskrun_attempt_id!=a.execution_attempt_id
           OR r.runtime_authority_id!=a.runtime_authority_id
           OR r.database_generation!=a.database_generation OR r.runtime_generation!=a.generation
           OR r.fencing_token!=a.fencing_token OR r.profile_digest!=a.profile_digest
           OR r.pricing_revision_digest!=a.pricing_revision_digest
           OR r.request_digest!=a.render_digest OR r.profile_digest!=d.profile_digest
           OR r.provider_id!=p.provider_id OR r.credential_realm!=c.provider_id
           OR (s.dispatch_attempt_id IS NOT NULL AND (g.grant_id IS NULL
               OR r.provider_id!=g.provider_id OR r.profile_id!=g.profile_id
               OR r.profile_digest!=g.profile_digest
               OR r.pricing_revision_digest!=g.pricing_revision_digest))
           OR length(r.ciphertext)!=r.plaintext_len+16",
        [],
        |row| row.get(0),
    )?;
    if invalid != 0 {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn v54_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.extend([
        "provider_remote_request_intents",
        "provider_remote_response_bindings",
    ]);
    triggers.extend_from_slice(V54_TRIGGERS);
    triggers.extend([
        ("schema_v12_fence_provider_remote_request_intents_insert", "CREATE TRIGGER \"schema_v12_fence_provider_remote_request_intents_insert\" AFTER INSERT ON \"provider_remote_request_intents\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_provider_remote_request_intents_update", "CREATE TRIGGER \"schema_v12_fence_provider_remote_request_intents_update\" AFTER UPDATE ON \"provider_remote_request_intents\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_provider_remote_request_intents_delete", "CREATE TRIGGER \"schema_v12_fence_provider_remote_request_intents_delete\" AFTER DELETE ON \"provider_remote_request_intents\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_provider_remote_response_bindings_insert", "CREATE TRIGGER \"schema_v12_fence_provider_remote_response_bindings_insert\" AFTER INSERT ON \"provider_remote_response_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_provider_remote_response_bindings_update", "CREATE TRIGGER \"schema_v12_fence_provider_remote_response_bindings_update\" AFTER UPDATE ON \"provider_remote_response_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ("schema_v12_fence_provider_remote_response_bindings_delete", "CREATE TRIGGER \"schema_v12_fence_provider_remote_response_bindings_delete\" AFTER DELETE ON \"provider_remote_response_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
    ]);
}
