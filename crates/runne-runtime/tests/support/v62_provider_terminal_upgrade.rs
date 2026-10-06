use rusqlite::Connection;

/// Rewinds v65, v64 and v63 extensions on a lawful current provider database
/// while preserving every pre-v63 row needed to verify the historical upgrade.
pub fn remove_v63_for_v62_upgrade(connection: &Connection, omit_v19_marker: bool) {
    let v65_triggers = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN (
                'permission_mode_selections','taskrun_tool_permission_admissions',
                'permission_mode_command_receipts','permission_mode_native_challenges')
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in v65_triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
            .unwrap();
    }
    let d21_cross_table_triggers = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger'
             AND name LIKE '%_d21' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in d21_cross_table_triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE permission_mode_native_challenges;
             DROP TABLE permission_mode_command_receipts;
             DROP TABLE taskrun_tool_permission_admissions;
             DROP TABLE permission_mode_selections;
             DELETE FROM schema_version WHERE version=65;",
        )
        .unwrap();
    let v64_triggers = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN (
                'taskrun_tool_invocations','taskrun_tool_budgets',
                'provider_terminal_application_kinds','taskrun_provider_round_bindings',
                'd2_tool_loop_completions') ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in v64_triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE d2_tool_loop_completions;
             DROP TABLE taskrun_provider_round_bindings;
             DROP TABLE taskrun_tool_budgets;
             DROP TABLE provider_terminal_application_kinds;
             DROP TABLE taskrun_tool_invocations;
             DELETE FROM schema_version WHERE version=64;",
        )
        .unwrap();
    let triggers = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger'
             AND (name LIKE 'provider_unknown_terminal_receipts%'
               OR name LIKE 'schema_v12_fence_provider_unknown_terminal_receipts_%')
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE provider_unknown_terminal_receipts;
             DELETE FROM schema_version WHERE version=63;",
        )
        .unwrap();
    if omit_v19_marker {
        connection
            .execute("DELETE FROM schema_version WHERE version=19", [])
            .unwrap();
    }
}
