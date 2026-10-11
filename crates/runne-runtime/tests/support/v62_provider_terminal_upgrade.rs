use rusqlite::Connection;

/// Rewinds v68 through v63 extensions on a lawful current provider database
/// while preserving every pre-v63 row needed to verify the historical upgrade.
pub fn remove_v63_for_v62_upgrade(connection: &Connection, omit_v19_marker: bool) {
    // v66..=v68 owned structures must be empty: dropping rows here would
    // silently discard evidence the caller's before/after snapshot compares.
    for table in [
        "permission_mode_native_challenges",
        "permission_mode_native_challenge_managed_identity",
        "permission_mode_command_receipt_managed_identity",
        "taskrun_local_permission_routes",
        "x2_permission_bindings",
        "x2_permission_human",
        "x2_permission_admission",
        "x2_permission_spent",
        "x2_permission_stop",
        "x2_permission_terminal",
    ] {
        let rows: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "v66..=v68 fixture table {table} must be empty");
    }
    drop_triggers_on(
        connection,
        "'taskrun_local_permission_routes','x2_permission_bindings','x2_permission_human',\
         'x2_permission_admission','x2_permission_spent','x2_permission_stop',\
         'x2_permission_terminal'",
    );
    connection
        .execute_batch(
            "DROP TABLE x2_permission_terminal;
             DROP TABLE x2_permission_stop;
             DROP TABLE x2_permission_spent;
             DROP TABLE x2_permission_admission;
             DROP TABLE x2_permission_human;
             DROP TABLE x2_permission_bindings;
             DROP TABLE taskrun_local_permission_routes;
             DELETE FROM schema_version WHERE version=68;",
        )
        .unwrap();
    drop_triggers_on(
        connection,
        "'permission_mode_native_challenge_managed_identity',\
         'permission_mode_command_receipt_managed_identity'",
    );
    connection
        .execute_batch(
            "DROP TABLE permission_mode_command_receipt_managed_identity;
             DROP TABLE permission_mode_native_challenge_managed_identity;
             DELETE FROM schema_version WHERE version=67;",
        )
        .unwrap();
    // v66 recreated permission_mode_native_challenges in place; the v65
    // rewind below drops that table, so only its marker remains to remove.
    connection
        .execute_batch("DELETE FROM schema_version WHERE version=66;")
        .unwrap();
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

fn drop_triggers_on(connection: &Connection, tables: &str) {
    let triggers = connection
        .prepare(&format!(
            "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN ({tables})
             ORDER BY name"
        ))
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
}
