pub(super) const MIGRATION_V67: &str = include_str!("v67_permission_managed_identity.sql");

const V67_TRIGGERS: &[(&str, &str)] = &[
    (
        "permission_mode_native_challenge_managed_identity_insert_guard",
        "CREATE TRIGGER permission_mode_native_challenge_managed_identity_insert_guard BEFORE INSERT ON permission_mode_native_challenge_managed_identity WHEN NOT EXISTS(SELECT 1 FROM permission_mode_native_challenges c WHERE c.challenge_id=NEW.challenge_id AND c.digest_version=2 AND c.state=1 AND c.confirmation_phase=1 AND c.project_id=NEW.project_id AND c.managed_policy_instance_epoch=NEW.record_instance_epoch AND c.managed_policy_revision=NEW.record_revision AND c.managed_policy_status=NEW.record_status AND c.managed_deny_mask=NEW.record_deny_mask AND c.challenge_binding_digest=NEW.envelope_digest) BEGIN SELECT RAISE(ABORT,'managed identity does not match issued challenge'); END",
    ),
    (
        "permission_mode_native_challenge_managed_identity_immutable",
        "CREATE TRIGGER permission_mode_native_challenge_managed_identity_immutable BEFORE UPDATE ON permission_mode_native_challenge_managed_identity BEGIN SELECT RAISE(ABORT,'issued managed identity is immutable'); END",
    ),
    (
        "permission_mode_native_challenge_managed_identity_no_delete",
        "CREATE TRIGGER permission_mode_native_challenge_managed_identity_no_delete BEFORE DELETE ON permission_mode_native_challenge_managed_identity BEGIN SELECT RAISE(ABORT,'issued managed identity is retained'); END",
    ),
    (
        "permission_mode_command_receipt_managed_identity_insert_guard",
        "CREATE TRIGGER permission_mode_command_receipt_managed_identity_insert_guard BEFORE INSERT ON permission_mode_command_receipt_managed_identity WHEN NOT EXISTS(SELECT 1 FROM permission_mode_command_receipts r JOIN permission_mode_native_challenges c ON c.command_id=NEW.command_id JOIN permission_mode_native_challenge_managed_identity m ON m.challenge_id=NEW.challenge_id WHERE c.state=2 AND c.confirmation_phase=2 AND c.digest_version=2 AND c.challenge_id=NEW.challenge_id AND r.runtime_authority_id=c.runtime_authority_id AND r.principal_id=c.principal_id AND r.workspace_id=c.workspace_id AND r.project_id=c.project_id AND r.idempotency_key=c.idempotency_key AND r.selected_mode=c.requested_mode AND r.preset_version=c.preset_version AND r.authorization_revision=NEW.authorization_revision AND r.authorization_revision=c.expected_authorization_revision+1 AND r.managed_policy_version=c.managed_policy_revision AND r.managed_policy_digest=c.managed_policy_digest AND m.encoding_tag=NEW.encoding_tag AND m.project_version=NEW.project_version AND m.canonical_digest=NEW.canonical_digest AND m.envelope_digest=NEW.envelope_digest) BEGIN SELECT RAISE(ABORT,'receipt managed identity does not match committed command'); END",
    ),
    (
        "permission_mode_command_receipt_managed_identity_immutable",
        "CREATE TRIGGER permission_mode_command_receipt_managed_identity_immutable BEFORE UPDATE ON permission_mode_command_receipt_managed_identity BEGIN SELECT RAISE(ABORT,'receipt managed identity is immutable'); END",
    ),
    (
        "permission_mode_command_receipt_managed_identity_no_delete",
        "CREATE TRIGGER permission_mode_command_receipt_managed_identity_no_delete BEFORE DELETE ON permission_mode_command_receipt_managed_identity BEGIN SELECT RAISE(ABORT,'receipt managed identity is retained'); END",
    ),
];

const V67_FENCE_TRIGGERS: &[(&str, &str)] = &[
    (
        "schema_v12_fence_permission_mode_native_challenge_managed_identity_insert",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenge_managed_identity_insert\" AFTER INSERT ON \"permission_mode_native_challenge_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_native_challenge_managed_identity_update",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenge_managed_identity_update\" AFTER UPDATE ON \"permission_mode_native_challenge_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_native_challenge_managed_identity_delete",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_native_challenge_managed_identity_delete\" AFTER DELETE ON \"permission_mode_native_challenge_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipt_managed_identity_insert",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipt_managed_identity_insert\" AFTER INSERT ON \"permission_mode_command_receipt_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipt_managed_identity_update",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipt_managed_identity_update\" AFTER UPDATE ON \"permission_mode_command_receipt_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_permission_mode_command_receipt_managed_identity_delete",
        "CREATE TRIGGER \"schema_v12_fence_permission_mode_command_receipt_managed_identity_delete\" AFTER DELETE ON \"permission_mode_command_receipt_managed_identity\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

pub(super) fn apply_v67_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute(
        "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=3
         WHERE state=1 AND confirmation_phase=1",
        [],
    )?;
    tx.execute_batch(MIGRATION_V67)?;
    for (_, sql) in V67_TRIGGERS.iter().chain(V67_FENCE_TRIGGERS) {
        tx.execute_batch(sql)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(67)", [])?;
    tx.commit()
}

pub(super) fn v67_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    let actual_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version),0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version != 67 || actual_version != 67 || !v64_matches(connection, 67)? {
        return Ok(false);
    }
    v67_structure_matches(connection)
}

pub(super) fn v67_structure_matches(connection: &Connection) -> SqliteResult<bool> {
    if !v66_structure_matches(connection)?
        || !table_sql_matches_migration(
            connection,
            "permission_mode_native_challenge_managed_identity",
            MIGRATION_V67,
        )?
        || !table_sql_matches_migration(
            connection,
            "permission_mode_command_receipt_managed_identity",
            MIGRATION_V67,
        )?
        || !v67_metadata_rows_match(connection)?
    {
        return Ok(false);
    }
    for (name, sql) in V67_TRIGGERS.iter().chain(V67_FENCE_TRIGGERS) {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn v67_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    v66_add_schema_extensions(tables, indexes, triggers);
    tables.extend_from_slice(&[
        "permission_mode_native_challenge_managed_identity",
        "permission_mode_command_receipt_managed_identity",
    ]);
    triggers.extend_from_slice(V67_TRIGGERS);
    triggers.extend_from_slice(V67_FENCE_TRIGGERS);
}

fn v67_metadata_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let invalid_challenges: i64 = connection.query_row(
        "SELECT COUNT(*) FROM permission_mode_native_challenge_managed_identity m
         JOIN permission_mode_native_challenges c USING(challenge_id)
         WHERE c.project_id!=m.project_id OR c.challenge_binding_digest!=m.envelope_digest
           OR c.managed_policy_instance_epoch!=m.record_instance_epoch
           OR c.managed_policy_revision!=m.record_revision
           OR c.managed_policy_status!=m.record_status OR c.managed_deny_mask!=m.record_deny_mask
           OR m.encoding_tag!=2",
        [],
        |row| row.get(0),
    )?;
    let invalid_receipts: i64 = connection.query_row(
        "SELECT COUNT(*) FROM permission_mode_command_receipt_managed_identity r
         JOIN permission_mode_command_receipts c USING(command_id)
         JOIN permission_mode_native_challenge_managed_identity m USING(challenge_id)
         WHERE r.encoding_tag!=m.encoding_tag OR r.project_version!=m.project_version
           OR r.canonical_digest!=m.canonical_digest OR r.envelope_digest!=m.envelope_digest
           OR r.authorization_revision!=c.authorization_revision",
        [],
        |row| row.get(0),
    )?;
    Ok(invalid_challenges == 0 && invalid_receipts == 0)
}
