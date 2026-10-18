pub(super) const MIGRATION_V66: &str = include_str!("v66_permission_confirmation.sql");

const V66_TRIGGERS: &[(&str, &str)] = &[(
    "permission_mode_native_confirmation_v2_update",
    "CREATE TRIGGER permission_mode_native_confirmation_v2_update BEFORE UPDATE ON permission_mode_native_challenges WHEN NEW.requested_mode!=OLD.requested_mode OR NEW.digest_version!=OLD.digest_version OR NEW.public_request_digest!=OLD.public_request_digest OR NEW.protected_session_id IS NOT OLD.protected_session_id OR OLD.confirmation_phase!=1 OR NEW.state NOT IN (2,3) OR (NEW.state=2 AND (NEW.confirmation_phase!=2 OR NEW.proof_identifier IS NULL OR NEW.proof_identifier!=NEW.challenge_binding_digest OR NEW.consumed_at_unix_ms IS NULL)) OR (NEW.state=3 AND (NEW.confirmation_phase NOT IN (3,4,5) OR NEW.proof_identifier IS NOT NULL OR NEW.consumed_at_unix_ms IS NOT NULL)) BEGIN SELECT RAISE(ABORT,'permission mode confirmation binding is immutable'); END",
)];

pub(super) fn apply_v66_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(
        "DROP TRIGGER permission_mode_native_challenge_update;
         DROP TRIGGER permission_mode_native_challenge_no_delete;
         DROP TRIGGER schema_v12_fence_permission_mode_native_challenges_insert;
         DROP TRIGGER schema_v12_fence_permission_mode_native_challenges_update;
         DROP TRIGGER schema_v12_fence_permission_mode_native_challenges_delete;
         DROP INDEX idx_permission_mode_challenges_pending;
         ALTER TABLE permission_mode_native_challenges RENAME TO permission_mode_native_challenges_v65;",
    )?;
    tx.execute_batch(MIGRATION_V66)?;
    for (name, sql) in V65_TRIGGERS
        .iter()
        .filter(|(name, _)| *name == "permission_mode_native_challenge_update")
    {
        let _ = name;
        tx.execute_batch(sql)?;
    }
    tx.execute_batch(
        "CREATE TRIGGER permission_mode_native_challenge_no_delete BEFORE DELETE ON permission_mode_native_challenges BEGIN SELECT RAISE(ABORT,'permission mode challenge history is retained'); END",
    )?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("permission_mode_native_challenges", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(66)", [])?;
    tx.commit()
}

pub(super) fn v66_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    let actual_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version),0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version != 66
        || actual_version != 66
        || !v64_matches(connection, 66)?
        || !v66_structure_matches(connection)?
    {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn v66_structure_matches(connection: &Connection) -> SqliteResult<bool> {
    if !table_sql_matches_migration(connection, "permission_mode_selections", MIGRATION_V65)?
        || !table_sql_matches_migration(
            connection,
            "taskrun_tool_permission_admissions",
            MIGRATION_V65,
        )?
        || !table_sql_matches_migration(
            connection,
            "permission_mode_command_receipts",
            MIGRATION_V65,
        )?
        || !table_sql_matches_migration(
            connection,
            "permission_mode_native_challenges",
            MIGRATION_V66,
        )?
        || !index_matches(
            connection,
            "idx_permission_mode_challenges_pending",
            "permission_mode_native_challenges",
            &[
                "runtime_authority_id",
                "principal_id",
                "workspace_id",
                "state",
                "expires_at_unix_ms",
            ],
        )?
    {
        return Ok(false);
    }
    for (name, sql) in V65_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    for (name, sql) in V66_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    for (name, sql) in V65_FENCE_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn v66_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    v65_add_schema_extensions(tables, indexes, triggers);
    triggers.extend_from_slice(V66_TRIGGERS);
}
