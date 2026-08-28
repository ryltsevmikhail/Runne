const V32_OPERATION_INDEXES: [&str; 2] = [
    "provider_credential_one_non_terminal_operation",
    "provider_credential_one_pending_legacy_source_cleanup",
];

pub(super) fn v32_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 32
        || !v30_predecessor_matches_with_v32(
            connection,
            &v32_insert_trigger(),
            &v32_head_active_lifecycle_trigger(),
        )?
        || !v32_operation_indexes_match(connection)?
    {
        return Ok(false);
    }
    for name in V30_TRIGGERS {
        if !v24_trigger_matches(connection, name, v30_trigger_source(name))? {
            return Ok(false);
        }
    }
    if !v24_trigger_matches(
        connection,
        "provider_credential_operation_insert_prepared",
        &v32_insert_trigger(),
    )? || !v24_trigger_matches(
        connection,
        "provider_credential_head_active_lifecycle",
        &v32_head_active_lifecycle_trigger(),
    )? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (32, 1, 31, 509) | (32, 1, 32, 528)))
}

fn v32_operation_index_names() -> &'static [&'static str] {
    &V32_OPERATION_INDEXES
}

fn v32_operation_indexes_match(connection: &Connection) -> SqliteResult<bool> {
    V32_OPERATION_INDEXES
        .into_iter()
        .try_fold(true, |matches, name| {
            let expected = MIGRATION_V32
                .split(';')
                .map(str::trim)
                .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")));
            Ok(matches && v24_index_matches_with_source(connection, name, expected)?)
        })
}

fn v32_head_active_lifecycle_trigger() -> String {
    v24_head_active_lifecycle_trigger().replacen(
        "o.action = 'MIGRATE_LEGACY' AND OLD.legacy_import_consumed = 0 AND NEW.legacy_import_consumed = 1 AND o.state = 'COMPLETED'",
        "o.action = 'MIGRATE_LEGACY' AND OLD.legacy_import_consumed = 0 AND NEW.legacy_import_consumed = 1 AND o.state = 'READBACK_VERIFIED'",
        1,
    )
}

fn v32_insert_trigger() -> String {
    let source = v25_trigger(
        "provider_credential_operation_insert_prepared",
        V24_TRIGGERS
            .iter()
            .find(|(name, _)| *name == "provider_credential_operation_insert_prepared")
            .expect("V24 insert trigger exists")
            .1,
    );
    source.replacen(
        "OR NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence",
        "OR NOT (NEW.action = 'LEGACY_SOURCE_CLEANUP' AND EXISTS(SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id = NEW.provider_id AND h.lifecycle_revision + 1 = NEW.expected_lifecycle_revision AND h.credential_fence + 1 = NEW.expected_credential_fence AND h.legacy_import_consumed = 0 AND h.active_credential_version IS NULL AND h.active_ref_digest IS NULL AND EXISTS(SELECT 1 FROM provider_credential_operations AS import WHERE import.provider_id = NEW.provider_id AND import.action = 'MIGRATE_LEGACY' AND import.expected_lifecycle_revision = h.lifecycle_revision AND import.expected_credential_fence = h.credential_fence AND import.state = 'READBACK_VERIFIED'))) AND NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence",
        1,
    )
}
