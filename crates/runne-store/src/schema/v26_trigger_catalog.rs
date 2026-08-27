use super::*;

pub(super) fn matches(connection: &Connection) -> SqliteResult<bool> {
    matches_with_additional(connection, &[])
}

pub(super) fn matches_with_additional(
    connection: &Connection,
    additional: &[(&str, &str)],
) -> SqliteResult<bool> {
    let mut expected = Vec::new();
    for table in authoritative_v12_tables(connection)? {
        for operation in ["insert", "update", "delete"] {
            let (name, source) = v12_fence_trigger(&table, operation);
            if !v24_trigger_matches(connection, &name, &source)? {
                return Ok(false);
            }
            expected.push(name);
        }
    }
    for (name, _, source) in v12_guard_triggers() {
        if !v24_trigger_matches(connection, name, source)? {
            return Ok(false);
        }
        expected.push(name.to_owned());
    }
    for (name, source) in V16_TRIGGERS.into_iter().chain(V17_TRIGGERS) {
        if !v24_trigger_matches(connection, name, source)? {
            return Ok(false);
        }
        expected.push(name.to_owned());
    }
    for (name, source) in inherited_successor_triggers() {
        if !v24_trigger_matches(connection, name, &source)? {
            return Ok(false);
        }
        expected.push(name.to_owned());
    }
    for (name, source) in V24_TRIGGERS {
        let source = if V25_REPLACED_TRIGGERS.contains(&name) {
            v25_trigger(name, source)
        } else {
            source.to_owned()
        };
        if !v24_trigger_matches(connection, name, &source)? {
            return Ok(false);
        }
        expected.push(name.to_owned());
    }
    for name in V26_TRIGGERS {
        if !v24_trigger_matches(connection, name, v26_trigger_source(name))? {
            return Ok(false);
        }
        expected.push(name.to_owned());
    }
    for (name, source) in additional {
        if !v24_trigger_matches(connection, name, source)? {
            return Ok(false);
        }
        expected.push((*name).to_owned());
    }
    let actual: usize = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
        [],
        |row| row.get(0),
    )?;
    Ok(actual == expected.len())
}

fn inherited_successor_triggers() -> [(&'static str, String); 4] {
    [
        (
            "global_command_id_from_command_receipts",
            "CREATE TRIGGER global_command_id_from_command_receipts BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END".to_owned(),
        ),
        (
            "global_command_id_from_project_workspace_receipts",
            "CREATE TRIGGER global_command_id_from_project_workspace_receipts BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END".to_owned(),
        ),
        (
            "aggregate_state_snapshots_bind_insert",
            replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER.to_owned(),
        ),
        (
            "aggregate_state_snapshots_bind_update",
            replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER.to_owned(),
        ),
    ]
}
