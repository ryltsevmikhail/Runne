pub(super) const MIGRATION_V52: &str = r#"
CREATE TABLE provider_secondary_profile_grants (
 grant_id BLOB PRIMARY KEY CHECK(length(grant_id)=16 AND grant_id!=zeroblob(16)),
 runtime_authority_id BLOB NOT NULL CHECK(length(runtime_authority_id)=16 AND runtime_authority_id!=zeroblob(16)),
 database_generation INTEGER NOT NULL CHECK(database_generation>0),
 provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 128),
 profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 128),
 credential_realm TEXT NOT NULL CHECK(length(credential_realm) BETWEEN 1 AND 128),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32 AND profile_digest!=zeroblob(32)),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32 AND pricing_revision_digest!=zeroblob(32)),
 token_budget_limit INTEGER NOT NULL CHECK(token_budget_limit>0),
 token_budget_reserved INTEGER NOT NULL CHECK(token_budget_reserved>=0 AND token_budget_reserved<=token_budget_limit),
 token_budget_settled INTEGER NOT NULL CHECK(token_budget_settled>=0 AND token_budget_reserved+token_budget_settled<=token_budget_limit),
 cost_budget_limit_micros INTEGER NOT NULL CHECK(cost_budget_limit_micros>0),
 cost_budget_reserved_micros INTEGER NOT NULL CHECK(cost_budget_reserved_micros>=0 AND cost_budget_reserved_micros<=cost_budget_limit_micros),
 cost_budget_settled_micros INTEGER NOT NULL CHECK(cost_budget_settled_micros>=0 AND cost_budget_reserved_micros+cost_budget_settled_micros<=cost_budget_limit_micros),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at>=created_at),
 UNIQUE(provider_id,profile_id),
 CHECK((enabled=1 AND revoked_at IS NULL) OR (enabled=0 AND revoked_at IS NOT NULL))
);
CREATE TRIGGER provider_secondary_profile_grants_identity_immutable BEFORE UPDATE ON provider_secondary_profile_grants
WHEN NEW.grant_id!=OLD.grant_id OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.provider_id!=OLD.provider_id OR NEW.profile_id!=OLD.profile_id OR NEW.credential_realm!=OLD.credential_realm OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.token_budget_limit!=OLD.token_budget_limit OR NEW.cost_budget_limit_micros!=OLD.cost_budget_limit_micros OR NEW.created_at!=OLD.created_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at) OR (OLD.enabled=0 AND NEW.enabled!=0)
BEGIN SELECT RAISE(ABORT,'Provider profile grant identity is immutable'); END;
CREATE TRIGGER provider_secondary_profile_grants_no_delete BEFORE DELETE ON provider_secondary_profile_grants BEGIN SELECT RAISE(ABORT,'Provider profile grant is retained'); END;
CREATE TABLE provider_secondary_profile_bindings (
 binding_id BLOB PRIMARY KEY CHECK(length(binding_id)=16 AND binding_id!=zeroblob(16)),
 grant_id BLOB NOT NULL CHECK(length(grant_id)=16 AND grant_id!=zeroblob(16)) REFERENCES provider_secondary_profile_grants(grant_id),
 owner_id TEXT NOT NULL CHECK(length(owner_id) BETWEEN 1 AND 256),
 authority_revision INTEGER NOT NULL CHECK(authority_revision>0),
 scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 256),
 activation_binding_kind TEXT NOT NULL CHECK(activation_binding_kind IN ('protected_v2','external_owner_private')),
 activation_binding_digest BLOB NOT NULL CHECK(length(activation_binding_digest)=32 AND activation_binding_digest!=zeroblob(32)),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 closed_at INTEGER CHECK(closed_at IS NULL OR closed_at>=created_at),
 close_reason TEXT CHECK(close_reason IS NULL OR close_reason IN ('renewed','revoked')),
 CHECK((closed_at IS NULL AND close_reason IS NULL) OR (closed_at IS NOT NULL AND close_reason IS NOT NULL))
);
CREATE UNIQUE INDEX provider_secondary_profile_bindings_one_active ON provider_secondary_profile_bindings(grant_id) WHERE closed_at IS NULL;
CREATE TRIGGER provider_secondary_profile_bindings_immutable BEFORE UPDATE ON provider_secondary_profile_bindings
WHEN NEW.binding_id!=OLD.binding_id OR NEW.grant_id!=OLD.grant_id OR NEW.owner_id!=OLD.owner_id OR NEW.authority_revision!=OLD.authority_revision OR NEW.scope!=OLD.scope OR NEW.activation_binding_kind!=OLD.activation_binding_kind OR NEW.activation_binding_digest!=OLD.activation_binding_digest OR NEW.created_at!=OLD.created_at OR (OLD.closed_at IS NOT NULL AND (NEW.closed_at IS NOT OLD.closed_at OR NEW.close_reason IS NOT OLD.close_reason)) OR (OLD.closed_at IS NULL AND (NEW.closed_at IS NULL OR NEW.close_reason IS NULL))
BEGIN SELECT RAISE(ABORT,'Provider profile authorization binding is immutable'); END;
CREATE TRIGGER provider_secondary_profile_bindings_no_delete BEFORE DELETE ON provider_secondary_profile_bindings BEGIN SELECT RAISE(ABORT,'Provider profile binding is retained'); END;
CREATE TABLE provider_secondary_profile_attempts (
 dispatch_attempt_id BLOB PRIMARY KEY CHECK(length(dispatch_attempt_id)=16 AND dispatch_attempt_id!=zeroblob(16)) REFERENCES provider_execution_admissions(dispatch_attempt_id),
 grant_id BLOB NOT NULL CHECK(length(grant_id)=16 AND grant_id!=zeroblob(16)) REFERENCES provider_secondary_profile_grants(grant_id),
 binding_id BLOB NOT NULL CHECK(length(binding_id)=16 AND binding_id!=zeroblob(16)) REFERENCES provider_secondary_profile_bindings(binding_id),
 provider_idempotency_key TEXT NOT NULL UNIQUE REFERENCES provider_execution_admissions(provider_idempotency_key),
 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32),
 pricing_revision_digest BLOB NOT NULL CHECK(length(pricing_revision_digest)=32)
);
CREATE TRIGGER provider_secondary_profile_attempts_immutable BEFORE UPDATE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is immutable'); END;
CREATE TRIGGER provider_secondary_profile_attempts_no_delete BEFORE DELETE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is retained'); END;
"#;

pub(super) fn apply_v52_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V52)?;
    for table in [
        "provider_secondary_profile_grants",
        "provider_secondary_profile_bindings",
        "provider_secondary_profile_attempts",
    ] {
        for operation in ["insert", "update", "delete"] {
            tx.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(52)", [])?;
    tx.commit()
}

pub(super) fn v52_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 52 {
        return Ok(false);
    }
    v52_base_matches(connection, version)
}

pub(super) fn v52_base_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 52..=63) {
        return Ok(false);
    }
    if !v51_base_matches(connection, version)? {
        return Ok(false);
    }
    for table in [
        "provider_secondary_profile_grants",
        "provider_secondary_profile_bindings",
        "provider_secondary_profile_attempts",
    ] {
        if !table_sql_matches_migration(connection, table, MIGRATION_V52)? {
            return Ok(false);
        }
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
    for (name, expected) in [
        (
            "provider_secondary_profile_grants_identity_immutable",
            "CREATE TRIGGER provider_secondary_profile_grants_identity_immutable BEFORE UPDATE ON provider_secondary_profile_grants WHEN NEW.grant_id!=OLD.grant_id OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.provider_id!=OLD.provider_id OR NEW.profile_id!=OLD.profile_id OR NEW.credential_realm!=OLD.credential_realm OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.token_budget_limit!=OLD.token_budget_limit OR NEW.cost_budget_limit_micros!=OLD.cost_budget_limit_micros OR NEW.created_at!=OLD.created_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at) OR (OLD.enabled=0 AND NEW.enabled!=0) BEGIN SELECT RAISE(ABORT,'Provider profile grant identity is immutable'); END",
        ),
        (
            "provider_secondary_profile_grants_no_delete",
            "CREATE TRIGGER provider_secondary_profile_grants_no_delete BEFORE DELETE ON provider_secondary_profile_grants BEGIN SELECT RAISE(ABORT,'Provider profile grant is retained'); END",
        ),
        (
            "provider_secondary_profile_bindings_immutable",
            "CREATE TRIGGER provider_secondary_profile_bindings_immutable BEFORE UPDATE ON provider_secondary_profile_bindings WHEN NEW.binding_id!=OLD.binding_id OR NEW.grant_id!=OLD.grant_id OR NEW.owner_id!=OLD.owner_id OR NEW.authority_revision!=OLD.authority_revision OR NEW.scope!=OLD.scope OR NEW.activation_binding_kind!=OLD.activation_binding_kind OR NEW.activation_binding_digest!=OLD.activation_binding_digest OR NEW.created_at!=OLD.created_at OR (OLD.closed_at IS NOT NULL AND (NEW.closed_at IS NOT OLD.closed_at OR NEW.close_reason IS NOT OLD.close_reason)) OR (OLD.closed_at IS NULL AND (NEW.closed_at IS NULL OR NEW.close_reason IS NULL)) BEGIN SELECT RAISE(ABORT,'Provider profile authorization binding is immutable'); END",
        ),
        (
            "provider_secondary_profile_bindings_no_delete",
            "CREATE TRIGGER provider_secondary_profile_bindings_no_delete BEFORE DELETE ON provider_secondary_profile_bindings BEGIN SELECT RAISE(ABORT,'Provider profile binding is retained'); END",
        ),
        (
            "provider_secondary_profile_attempts_immutable",
            "CREATE TRIGGER provider_secondary_profile_attempts_immutable BEFORE UPDATE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is immutable'); END",
        ),
        (
            "provider_secondary_profile_attempts_no_delete",
            "CREATE TRIGGER provider_secondary_profile_attempts_no_delete BEFORE DELETE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is retained'); END",
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
    let index: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='index' AND name='provider_secondary_profile_bindings_one_active'", [], |row| row.get(0)).optional()?;
    if index.is_none_or(|sql| normalize_sql(&sql) != normalize_sql("CREATE UNIQUE INDEX provider_secondary_profile_bindings_one_active ON provider_secondary_profile_bindings(grant_id) WHERE closed_at IS NULL")) { return Ok(false); }
    secondary_profile_attempts_match(connection)
}

fn secondary_profile_attempts_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid_bindings: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM provider_secondary_profile_bindings binding
            LEFT JOIN provider_secondary_profile_grants grant_row USING(grant_id)
            WHERE grant_row.grant_id IS NULL)
           +
           (SELECT COUNT(*) FROM provider_secondary_profile_grants grant_row
            WHERE (grant_row.enabled=1 AND NOT EXISTS(
                      SELECT 1 FROM provider_secondary_profile_bindings current
                      WHERE current.grant_id=grant_row.grant_id AND current.closed_at IS NULL))
               OR (grant_row.enabled=0 AND EXISTS(
                      SELECT 1 FROM provider_secondary_profile_bindings current
                      WHERE current.grant_id=grant_row.grant_id AND current.closed_at IS NULL)))",
        [],
        |row| row.get(0),
    )?;
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_secondary_profile_attempts binding
         LEFT JOIN provider_execution_admissions admission USING(dispatch_attempt_id)
         LEFT JOIN provider_secondary_profile_grants grant_row USING(grant_id)
         LEFT JOIN provider_secondary_profile_bindings auth ON auth.binding_id=binding.binding_id
         WHERE admission.dispatch_attempt_id IS NULL OR grant_row.grant_id IS NULL OR auth.binding_id IS NULL
            OR auth.grant_id!=grant_row.grant_id OR admission.provider_idempotency_key!=binding.provider_idempotency_key
            OR admission.runtime_authority_id!=grant_row.runtime_authority_id
            OR admission.database_generation!=grant_row.database_generation
            OR admission.owner_id!=auth.owner_id OR admission.scope!=auth.scope
            OR admission.authority_revision!=auth.authority_revision
            OR admission.activation_binding_kind!=auth.activation_binding_kind
            OR admission.activation_binding_digest!=auth.activation_binding_digest
            OR admission.profile_digest!=binding.profile_digest OR admission.pricing_revision_digest!=binding.pricing_revision_digest
            OR grant_row.profile_digest!=binding.profile_digest OR grant_row.pricing_revision_digest!=binding.pricing_revision_digest",
        [], |row| row.get(0),
    )?;
    Ok(invalid == 0 && invalid_bindings == 0)
}
