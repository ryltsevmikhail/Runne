const V33_TABLE: &str = "credential_cleanup_recovery_attempts";
const V33_INDEX: &str = "credential_cleanup_recovery_one_live";
const V33_TRIGGERS: [&str; 3] = [
    "credential_cleanup_recovery_insert",
    "credential_cleanup_recovery_immutable",
    "credential_cleanup_recovery_no_delete",
];

#[derive(Default)]
struct CredentialSchemaExtensions<'a> {
    tables: &'a [&'a str],
    indexes: &'a [&'a str],
    triggers: &'a [(&'a str, &'a str)],
    replacements: &'a [(&'a str, &'a str)],
}

pub(super) fn v33_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    v33_family_matches(connection, version, false)
}

fn v33_family_matches(connection: &Connection, version: i64, cleanup_completion: bool) -> SqliteResult<bool> {
    let triggers = V33_TRIGGERS.map(|name| (name, v33_trigger_source(name)));
    let attachment = if cleanup_completion { v34_attachment_trigger() } else { v33_attachment_trigger() };
    let ticket = v33_ticket_trigger();
    let mut replacements = vec![
        ("provider_credential_attachment_insert", attachment.as_str()),
        ("provider_credential_ticket_insert_issued", ticket.as_str()),
    ];
    let completion = v34_completion_trigger();
    let recovery = v34_recovery_trigger();
    if cleanup_completion {
        replacements.push(("provider_credential_completion_receipt_insert", completion.as_str()));
        replacements.push(("credential_cleanup_recovery_insert", recovery.as_str()));
    }
    let extensions = CredentialSchemaExtensions {
        tables: &[V33_TABLE],
        indexes: &[V33_INDEX],
        triggers: &triggers,
        replacements: &replacements,
    };
    if version != if cleanup_completion { 34 } else { 33 }
        || !v30_predecessor_matches_with_successors(
            connection,
            &v32_insert_trigger(),
            &v32_head_active_lifecycle_trigger(),
            v32_operation_index_names(),
            &extensions,
            false,
            false,
        )?
        || !v30_columns_match(connection)?
        || !table_sql_matches_migration(connection, V29_TABLE, MIGRATION_V29)?
        || !table_sql_matches_migration(connection, V33_TABLE, MIGRATION_V33)?
        || !v24_index_matches_with_source(
            connection,
            V33_INDEX,
            MIGRATION_V33.split(';').map(str::trim)
                .find(|sql| sql.starts_with("CREATE UNIQUE INDEX credential_cleanup_recovery_one_live")),
        )?
    {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(if cleanup_completion {
        matches!(marker, (34, 1, 33, 576) | (34, 1, 34, 595))
    } else {
        matches!(marker, (33, 1, 32, 542) | (33, 1, 33, 561))
    })
}

fn v33_trigger_source(name: &str) -> &'static str {
    let start = MIGRATION_V33.find(&format!("CREATE TRIGGER {name}"))
        .expect("V33 trigger exists");
    let end = MIGRATION_V33[start..].find("END;").expect("V33 trigger ends") + start + 4;
    &MIGRATION_V33[start..end]
}
