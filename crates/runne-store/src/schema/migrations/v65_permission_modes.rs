pub(super) const MIGRATION_V65: &str = include_str!("v65_permission_modes.sql");

const V65_TRIGGERS: &[(&str, &str)] = &[
    (
        "permission_mode_selection_insert_revision",
        "CREATE TRIGGER permission_mode_selection_insert_revision BEFORE INSERT ON permission_mode_selections WHEN NEW.authorization_revision!=1 BEGIN SELECT RAISE(ABORT,'permission mode selection must start at revision one'); END",
    ),
    (
        "permission_mode_selection_revision_step",
        "CREATE TRIGGER permission_mode_selection_revision_step BEFORE UPDATE ON permission_mode_selections WHEN NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.principal_id!=OLD.principal_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.authorization_revision!=OLD.authorization_revision+1 BEGIN SELECT RAISE(ABORT,'permission mode selection identity or revision is invalid'); END",
    ),
    (
        "permission_mode_selection_no_delete",
        "CREATE TRIGGER permission_mode_selection_no_delete BEFORE DELETE ON permission_mode_selections BEGIN SELECT RAISE(ABORT,'permission mode selection history is retained'); END",
    ),
    (
        "taskrun_tool_permission_admission_immutable",
        "CREATE TRIGGER taskrun_tool_permission_admission_immutable BEFORE UPDATE ON taskrun_tool_permission_admissions BEGIN SELECT RAISE(ABORT,'tool permission admission is immutable'); END",
    ),
    (
        "taskrun_tool_permission_admission_no_delete",
        "CREATE TRIGGER taskrun_tool_permission_admission_no_delete BEFORE DELETE ON taskrun_tool_permission_admissions BEGIN SELECT RAISE(ABORT,'tool permission admission history is retained'); END",
    ),
    (
        "permission_mode_receipt_id_global",
        "CREATE TRIGGER permission_mode_receipt_id_global BEFORE INSERT ON permission_mode_command_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'permission mode command id already exists'); END",
    ),
    (
        "permission_mode_command_receipt_immutable",
        "CREATE TRIGGER permission_mode_command_receipt_immutable BEFORE UPDATE ON permission_mode_command_receipts BEGIN SELECT RAISE(ABORT,'permission mode command receipts are immutable'); END",
    ),
    (
        "permission_mode_command_receipt_no_delete",
        "CREATE TRIGGER permission_mode_command_receipt_no_delete BEFORE DELETE ON permission_mode_command_receipts BEGIN SELECT RAISE(ABORT,'permission mode command receipts are retained'); END",
    ),
    (
        "command_receipt_id_global_d21",
        "CREATE TRIGGER command_receipt_id_global_d21 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM permission_mode_command_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'command id already exists in permission mode receipts'); END",
    ),
    (
        "project_workspace_receipt_id_global_d21",
        "CREATE TRIGGER project_workspace_receipt_id_global_d21 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM permission_mode_command_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'command id already exists in permission mode receipts'); END",
    ),
    (
        "permission_mode_native_challenge_update",
        "CREATE TRIGGER permission_mode_native_challenge_update BEFORE UPDATE ON permission_mode_native_challenges WHEN NEW.challenge_id!=OLD.challenge_id OR NEW.nonce!=OLD.nonce OR NEW.challenge_binding_digest!=OLD.challenge_binding_digest OR NEW.request_digest!=OLD.request_digest OR NEW.command_id!=OLD.command_id OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.principal_id!=OLD.principal_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.project_id!=OLD.project_id OR NEW.workspace_version!=OLD.workspace_version OR NEW.idempotency_key!=OLD.idempotency_key OR NEW.store_authority_id!=OLD.store_authority_id OR NEW.store_lineage_id!=OLD.store_lineage_id OR NEW.expected_authorization_revision!=OLD.expected_authorization_revision OR NEW.preset_version!=OLD.preset_version OR NEW.managed_policy_instance_epoch!=OLD.managed_policy_instance_epoch OR NEW.managed_policy_revision!=OLD.managed_policy_revision OR NEW.managed_policy_status!=OLD.managed_policy_status OR NEW.managed_deny_mask!=OLD.managed_deny_mask OR NEW.managed_policy_digest!=OLD.managed_policy_digest OR NEW.mode_expires_at_unix_ms IS NOT OLD.mode_expires_at_unix_ms OR NEW.launch_authority_id!=OLD.launch_authority_id OR NEW.desktop_host_instance_id!=OLD.desktop_host_instance_id OR NEW.daemon_instance_id!=OLD.daemon_instance_id OR NEW.launch_generation!=OLD.launch_generation OR NEW.native_key_epoch!=OLD.native_key_epoch OR NEW.native_warning_version!=OLD.native_warning_version OR NEW.issued_at_unix_ms!=OLD.issued_at_unix_ms OR NEW.expires_at_unix_ms!=OLD.expires_at_unix_ms OR OLD.state!=1 OR NEW.state NOT IN (2,3) BEGIN SELECT RAISE(ABORT,'permission mode challenge binding is immutable'); END",
    ),
    (
        "permission_mode_native_challenge_no_delete",
        "CREATE TRIGGER permission_mode_native_challenge_no_delete BEFORE DELETE ON permission_mode_native_challenges BEGIN SELECT RAISE(ABORT,'permission mode challenge history is retained'); END",
    ),
];

const V65_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_permission_mode_selections_insert",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_selections_insert\" AFTER INSERT ON \"permission_mode_selections\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_selections_update",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_selections_update\" AFTER UPDATE ON \"permission_mode_selections\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_selections_delete",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_selections_delete\" AFTER DELETE ON \"permission_mode_selections\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_tool_permission_admissions_insert",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_permission_admissions_insert\" AFTER INSERT ON \"taskrun_tool_permission_admissions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_tool_permission_admissions_update",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_permission_admissions_update\" AFTER UPDATE ON \"taskrun_tool_permission_admissions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_taskrun_tool_permission_admissions_delete",
        "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_permission_admissions_delete\" AFTER DELETE ON \"taskrun_tool_permission_admissions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipts_insert",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipts_insert\" AFTER INSERT ON \"permission_mode_command_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipts_update",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipts_update\" AFTER UPDATE ON \"permission_mode_command_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipts_delete",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipts_delete\" AFTER DELETE ON \"permission_mode_command_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_native_challenges_insert",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenges_insert\" AFTER INSERT ON \"permission_mode_native_challenges\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_native_challenges_update",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenges_update\" AFTER UPDATE ON \"permission_mode_native_challenges\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_native_challenges_delete",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenges_delete\" AFTER DELETE ON \"permission_mode_native_challenges\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

pub(super) fn apply_v65_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V65)?;
    for table in [
        "permission_mode_selections",
        "taskrun_tool_permission_admissions",
        "permission_mode_command_receipts",
        "permission_mode_native_challenges",
    ] {
        for operation in ["insert", "update", "delete"] {
            transaction.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    transaction.execute("INSERT INTO schema_version(version) VALUES(65)", [])?;
    transaction.commit()
}

pub(super) fn v65_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version == 68 {
        return v68_matches(connection, version);
    }
    if version == 67 {
        return v67_matches(connection, version);
    }
    if version == 66 {
        // Existing callers use this lineage check for the current schema.
        // The V66 matcher validates the exact V65 prefix and V66 extensions.
        return v66_matches(connection, version);
    }
    if version != 65
        || !v64_matches(connection, version)?
        || !table_sql_matches_migration(connection, "permission_mode_selections", MIGRATION_V65)?
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
            MIGRATION_V65,
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
    for (name, sql) in V65_FENCE_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn v65_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.extend_from_slice(&[
        "permission_mode_selections",
        "taskrun_tool_permission_admissions",
        "permission_mode_command_receipts",
        "permission_mode_native_challenges",
    ]);
    indexes.push("idx_permission_mode_challenges_pending");
    triggers.extend_from_slice(V65_TRIGGERS);
    triggers.extend_from_slice(V65_FENCE_TRIGGERS);
}
