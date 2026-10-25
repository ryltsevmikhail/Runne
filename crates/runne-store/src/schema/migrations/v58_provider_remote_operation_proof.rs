include!("v58_provider_remote_operation_proof_match.rs");

pub(super) const MIGRATION_V58: &str = r#"
CREATE TABLE provider_remote_operation_proofs (
 nonce BLOB PRIMARY KEY CHECK(length(nonce)=16 AND nonce!=zeroblob(16)),
 dispatch_attempt_id BLOB NOT NULL CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 taskrun_attempt_id BLOB NOT NULL CHECK(length(taskrun_attempt_id)=16 AND taskrun_attempt_id!=zeroblob(16)),
 provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
 credential_realm TEXT NOT NULL CHECK(length(credential_realm) BETWEEN 1 AND 128),
 profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 128),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32 AND request_digest!=zeroblob(32)),
 response_id_digest BLOB NOT NULL CHECK(length(response_id_digest)=32 AND response_id_digest!=zeroblob(32)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 fencing_token INTEGER NOT NULL CHECK(fencing_token>0),
 key_id BLOB NOT NULL CHECK(length(key_id)=16 AND key_id!=zeroblob(16)),
 key_version INTEGER NOT NULL CHECK(key_version>0),
 operation INTEGER NOT NULL CHECK(operation IN (1,3)),
 issued_at INTEGER NOT NULL CHECK(issued_at>=0),
 expires_at INTEGER NOT NULL CHECK(expires_at>issued_at),
 state INTEGER NOT NULL CHECK(state IN (1,2,3)),
 observed_at INTEGER CHECK(observed_at IS NULL OR observed_at>=issued_at),
 observation_status INTEGER CHECK(observation_status IS NULL OR observation_status IN (1,2)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_remote_response_bindings(dispatch_attempt_id),
 CHECK((state=1 AND observed_at IS NULL AND observation_status IS NULL)
    OR (state=2 AND observed_at IS NOT NULL)
    OR (state=3 AND observed_at IS NOT NULL AND observation_status IS NULL))
);
CREATE UNIQUE INDEX provider_remote_operation_one_pending
 ON provider_remote_operation_proofs(dispatch_attempt_id) WHERE state=1;
CREATE TRIGGER provider_remote_operation_proofs_identity_immutable
 BEFORE UPDATE ON provider_remote_operation_proofs
 WHEN NEW.nonce!=OLD.nonce OR NEW.dispatch_attempt_id!=OLD.dispatch_attempt_id
 OR NEW.taskrun_id!=OLD.taskrun_id OR NEW.taskrun_attempt_id!=OLD.taskrun_attempt_id
 OR NEW.provider_id!=OLD.provider_id OR NEW.credential_realm!=OLD.credential_realm
 OR NEW.profile_id!=OLD.profile_id OR NEW.profile_digest!=OLD.profile_digest
 OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.request_digest!=OLD.request_digest
 OR NEW.response_id_digest!=OLD.response_id_digest OR NEW.runtime_authority_id!=OLD.runtime_authority_id
 OR NEW.database_generation!=OLD.database_generation OR NEW.runtime_generation!=OLD.runtime_generation
 OR NEW.fencing_token!=OLD.fencing_token OR NEW.key_id!=OLD.key_id OR NEW.key_version!=OLD.key_version
 OR NEW.operation!=OLD.operation OR NEW.issued_at!=OLD.issued_at OR NEW.expires_at!=OLD.expires_at
 BEGIN SELECT RAISE(ABORT,'provider remote operation proof identity is immutable'); END;
CREATE TRIGGER provider_remote_operation_proofs_state_transition
 BEFORE UPDATE ON provider_remote_operation_proofs
 WHEN NOT (OLD.state=1 AND NEW.state IN (2,3))
 BEGIN SELECT RAISE(ABORT,'provider remote operation proof is single use'); END;
CREATE TRIGGER provider_remote_operation_proofs_no_delete
 BEFORE DELETE ON provider_remote_operation_proofs
 BEGIN SELECT RAISE(ABORT,'provider remote operation proof is append only'); END;
"#;

pub(super) fn apply_v58_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V58)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("provider_remote_operation_proofs", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(58)", [])?;
    tx.commit()
}

pub(super) fn v58_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 58..=69)
        || !v57_matches(connection, version)?
        || !table_sql_matches_migration(
            connection,
            "provider_remote_operation_proofs",
            MIGRATION_V58,
        )?
    {
        return Ok(false);
    }
    for (name, expected) in V58_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("provider_remote_operation_proofs", operation);
        if !schema_trigger_matches(connection, &name, &expected)? {
            return Ok(false);
        }
    }
    v58_rows_match(connection)
}

pub(super) fn v58_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.push("provider_remote_operation_proofs");
    indexes.push("provider_remote_operation_one_pending");
    triggers.extend_from_slice(V58_TRIGGERS);
    triggers.extend_from_slice(V58_FENCE_TRIGGERS);
}

const V58_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_remote_operation_proofs_identity_immutable",
        "CREATE TRIGGER provider_remote_operation_proofs_identity_immutable BEFORE UPDATE ON provider_remote_operation_proofs WHEN NEW.nonce!=OLD.nonce OR NEW.dispatch_attempt_id!=OLD.dispatch_attempt_id OR NEW.taskrun_id!=OLD.taskrun_id OR NEW.taskrun_attempt_id!=OLD.taskrun_attempt_id OR NEW.provider_id!=OLD.provider_id OR NEW.credential_realm!=OLD.credential_realm OR NEW.profile_id!=OLD.profile_id OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.request_digest!=OLD.request_digest OR NEW.response_id_digest!=OLD.response_id_digest OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.runtime_generation!=OLD.runtime_generation OR NEW.fencing_token!=OLD.fencing_token OR NEW.key_id!=OLD.key_id OR NEW.key_version!=OLD.key_version OR NEW.operation!=OLD.operation OR NEW.issued_at!=OLD.issued_at OR NEW.expires_at!=OLD.expires_at BEGIN SELECT RAISE(ABORT,'provider remote operation proof identity is immutable'); END",
    ),
    (
        "provider_remote_operation_proofs_state_transition",
        "CREATE TRIGGER provider_remote_operation_proofs_state_transition BEFORE UPDATE ON provider_remote_operation_proofs WHEN NOT (OLD.state=1 AND NEW.state IN (2,3)) BEGIN SELECT RAISE(ABORT,'provider remote operation proof is single use'); END",
    ),
    (
        "provider_remote_operation_proofs_no_delete",
        "CREATE TRIGGER provider_remote_operation_proofs_no_delete BEFORE DELETE ON provider_remote_operation_proofs BEGIN SELECT RAISE(ABORT,'provider remote operation proof is append only'); END",
    ),
];

const V58_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_provider_remote_operation_proofs_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_operation_proofs_insert\" AFTER INSERT ON \"provider_remote_operation_proofs\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_operation_proofs_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_operation_proofs_update\" AFTER UPDATE ON \"provider_remote_operation_proofs\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_remote_operation_proofs_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_remote_operation_proofs_delete\" AFTER DELETE ON \"provider_remote_operation_proofs\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];
