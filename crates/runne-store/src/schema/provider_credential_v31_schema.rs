pub(super) fn v31_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 31 || !v30_predecessor_matches_with(connection, &v31_trigger())? {
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
        &v31_trigger(),
    )? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (31, 1, 30, 477) | (31, 1, 31, 496)))
}

pub(super) fn v31_trigger() -> String {
    let source = v25_trigger(
        "provider_credential_operation_insert_prepared",
        V24_TRIGGERS
            .iter()
            .find(|(name, _)| *name == "provider_credential_operation_insert_prepared")
            .expect("V24 insert trigger exists")
            .1,
    );
    source.replacen(
        "AND NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence",
        "AND NOT (NEW.action = 'LEGACY_SOURCE_CLEANUP' AND EXISTS(SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id = NEW.provider_id AND h.lifecycle_revision + 1 = NEW.expected_lifecycle_revision AND h.credential_fence + 1 = NEW.expected_credential_fence AND h.legacy_import_consumed = 0 AND h.active_credential_version IS NULL AND h.active_ref_digest IS NULL AND EXISTS(SELECT 1 FROM provider_credential_operations AS import WHERE import.provider_id = NEW.provider_id AND import.action = 'MIGRATE_LEGACY' AND import.expected_lifecycle_revision = h.lifecycle_revision AND import.expected_credential_fence = h.credential_fence AND import.state = 'READBACK_VERIFIED'))) AND NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence",
        1,
    )
}
