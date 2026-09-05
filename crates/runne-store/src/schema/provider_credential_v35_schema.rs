const V35_OPERATION_INDEXES: [&str; 3] = [
    "provider_credential_one_non_terminal_operation",
    "provider_credential_one_pending_legacy_source_cleanup",
    "provider_credential_one_pending_retired_version_cleanup",
];

fn v35_operation_index_names() -> &'static [&'static str] {
    &V35_OPERATION_INDEXES
}

fn v35_operation_indexes_match(connection: &Connection) -> SqliteResult<bool> {
    V35_OPERATION_INDEXES
        .into_iter()
        .try_fold(true, |matches, name| {
            let expected = if name == "provider_credential_one_pending_legacy_source_cleanup" {
                MIGRATION_V32
                    .split(';')
                    .map(str::trim)
                    .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")))
            } else {
                MIGRATION_V35
                    .split(';')
                    .map(str::trim)
                    .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")))
            };
            Ok(matches && v24_index_matches_with_source(connection, name, expected)?)
        })
}

pub(super) fn v35_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 35 || !v35_catalog_matches(connection, &[])? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (35, 1, 34, 611) | (35, 1, 35, 630)))
}

fn v35_catalog_matches(
    connection: &Connection,
    additional_triggers: &[(&str, &str)],
) -> SqliteResult<bool> {
    let mut triggers = V33_TRIGGERS
        .map(|name| (name, v33_trigger_source(name)))
        .to_vec();
    triggers.extend_from_slice(additional_triggers);
    let attachment = v34_attachment_trigger();
    let ticket = v33_ticket_trigger();
    let completion = v34_completion_trigger();
    let recovery = v34_recovery_trigger();
    let replacements = [
        ("provider_credential_attachment_insert", attachment.as_str()),
        ("provider_credential_ticket_insert_issued", ticket.as_str()),
        ("provider_credential_completion_receipt_insert", completion.as_str()),
        ("credential_cleanup_recovery_insert", recovery.as_str()),
    ];
    let extensions = CredentialSchemaExtensions {
        tables: &[V33_TABLE],
        indexes: &[V33_INDEX],
        triggers: &triggers,
        replacements: &replacements,
    };
    if !v30_predecessor_matches_with_successors(
            connection,
            &v32_insert_trigger(),
            &v32_head_active_lifecycle_trigger(),
            v35_operation_index_names(),
            &extensions,
        )?
        || !v30_columns_match(connection)?
        || !table_sql_matches_migration(connection, V29_TABLE, MIGRATION_V29)?
        || !table_sql_matches_migration(connection, V33_TABLE, MIGRATION_V33)?
        || !v24_index_matches_with_source(
            connection,
            V33_INDEX,
            MIGRATION_V33
                .split(';')
                .map(str::trim)
                .find(|sql| sql.starts_with("CREATE UNIQUE INDEX credential_cleanup_recovery_one_live")),
        )?
    {
        return Ok(false);
    }
    Ok(true)
}
