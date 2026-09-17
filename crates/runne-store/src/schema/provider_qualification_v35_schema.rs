const V35_TABLE: &str = "provider_qualification_admission_fences";
const V35_TRIGGERS: [&str; 5] = [
    "provider_qualification_fence_replay_conflict",
    "provider_qualification_fence_insert_guard",
    "provider_qualification_fence_selector_role",
    "provider_qualification_fence_no_update",
    "provider_qualification_fence_no_delete",
];

pub(super) fn v35_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 35 {
        return Ok(false);
    }
    if !v35_structure_matches(connection)? { return Ok(false); }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (35, 1, 34, 611) | (35, 1, 35, 630)))
}

pub(super) fn v35_structure_matches(connection: &Connection) -> SqliteResult<bool> {
    v35_structure_matches_with_v36_receipt(connection, false)
}

pub(super) fn v35_structure_matches_with_v36_receipt(connection: &Connection, allows_v36_project_receipt: bool) -> SqliteResult<bool> {
    let mut triggers = V33_TRIGGERS
        .map(|name| (name, v33_trigger_source(name)))
        .to_vec();
    triggers.extend(V35_TRIGGERS.map(|name| (name, v35_trigger_source(name))));
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
        tables: &[V33_TABLE, V35_TABLE],
        indexes: &[V33_INDEX],
        triggers: &triggers,
        replacements: &replacements,
    };
    if !v30_predecessor_matches_with_successors(
        connection,
        &v32_insert_trigger(),
        &v32_head_active_lifecycle_trigger(),
        true,
        &extensions,
        allows_v36_project_receipt,
    )?
        || !v30_columns_match(connection)?
        || !table_sql_matches_migration(connection, V29_TABLE, MIGRATION_V29)?
        || !table_sql_matches_migration(connection, V33_TABLE, MIGRATION_V33)?
        || !v35_table_matches(connection)?
        || !v24_index_matches_with_source(
            connection,
            V33_INDEX,
            MIGRATION_V33.split(';').map(str::trim).find(|sql| {
                sql.starts_with("CREATE UNIQUE INDEX credential_cleanup_recovery_one_live")
            }),
        )?
    {
        return Ok(false);
    }
    Ok(true)
}

fn v35_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [V35_TABLE],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V35
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {V35_TABLE} ")));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| {
            normalize_v24_ddl(&actual) == normalize_v24_ddl(expected)
        })
    }))
}

fn v35_trigger_source(name: &str) -> &'static str {
    let start = MIGRATION_V35
        .find(&format!("CREATE TRIGGER {name}"))
        .expect("V35 trigger exists");
    let end = MIGRATION_V35[start..]
        .find("END;")
        .expect("V35 trigger ends")
        + start
        + 4;
    &MIGRATION_V35[start..end]
}
