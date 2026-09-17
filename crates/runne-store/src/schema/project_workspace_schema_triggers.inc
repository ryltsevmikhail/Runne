fn global_command_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "global_command_id_from_command_receipts",
            GLOBAL_COMMAND_RECEIPT_TRIGGER,
        ),
        (
            "global_command_id_from_project_workspace_receipts",
            GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER,
        ),
    ]
    .into_iter()
    .try_fold(true, |valid, (name, expected)| {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(valid
            && actual.is_some_and(|sql| {
                super::normalize_sql(expected.trim().trim_end_matches(';'))
                    == super::normalize_sql(&sql)
            }))
    })
}
