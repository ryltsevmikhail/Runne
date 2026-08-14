use gocode_application::ports::{TextGenerationPhase, TextGenerationReceipt};
use gocode_domain::id::CommandId;

use super::fixture::*;

const LIFECYCLE_TABLES: &[&str] = &[
    "provider_terminal_outbox",
    "provider_dispatch_attempts",
    "events",
    "command_receipts",
    "aggregate_streams",
    "aggregate_state_snapshots",
    "event_log_state",
];

fn column(columns: &[String], name: &str) -> usize {
    columns.iter().position(|column| column == name).unwrap()
}

fn blob(bytes: &[u8]) -> String {
    format!("X'{}'", hex::encode_upper(bytes))
}

fn singleton_row<'a>(snapshot: &'a Snapshot, table: &str) -> &'a Vec<String> {
    let rows = &snapshot[table];
    assert_eq!(rows.len(), 1, "unexpected {table} cardinality");
    &rows[0]
}

fn dispatch_row_for_state<'a>(snapshot: &'a Snapshot, path: &str, state: i64) -> &'a Vec<String> {
    let state_column = column(&table_columns(path, "provider_dispatch_attempts"), "state");
    let rows = snapshot["provider_dispatch_attempts"]
        .iter()
        .filter(|row| row[state_column] == state.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        1,
        "unexpected dispatch state {state} cardinality"
    );
    rows[0]
}

pub(super) fn assert_completed_receipt(
    receipt: &TextGenerationReceipt,
    started: &TextGenerationReceipt,
) {
    assert_eq!(receipt.phase, TextGenerationPhase::Completed);
    assert_eq!(receipt.workspace_id, started.workspace_id);
    assert_eq!(receipt.conversation_id, started.conversation_id);
    assert_eq!(receipt.taskrun_id, started.taskrun_id);
    assert_eq!(receipt.attempt_id, started.attempt_id);
    assert_eq!(receipt.user_message_id, started.user_message_id);
    assert_eq!(receipt.assistant_message_id, started.assistant_message_id);
    assert_eq!(
        receipt.conversation_version,
        started.conversation_version + 1
    );
    assert_eq!(receipt.taskrun_version, started.taskrun_version + 1);
}

pub(super) fn assert_expected_terminal_recovery_delta(
    before: &Snapshot,
    after: &Snapshot,
    path: &str,
    command_id: CommandId,
    started: &TextGenerationReceipt,
    allow_authority_renewal: bool,
    allow_credential_rotation: bool,
) {
    let mut allowed = LIFECYCLE_TABLES.to_vec();
    if allow_authority_renewal {
        allowed.push("provider_runtime_authority_state");
    }
    if allow_credential_rotation {
        allowed.push("provider_credential_versions");
        allowed.push("provider_credential_provisions");
        allowed.push("provider_credential_clock_high_water");
    }
    assert_unchanged_except(before, after, &allowed);
    let outbox_columns = table_columns(path, "provider_terminal_outbox");
    let dispatch_columns = table_columns(path, "provider_dispatch_attempts");
    let before_outbox = singleton_row(before, "provider_terminal_outbox");
    let after_outbox = singleton_row(after, "provider_terminal_outbox");
    for (index, name) in outbox_columns.iter().enumerate() {
        if !["state", "receipt_digest", "applied_at"].contains(&name.as_str()) {
            assert_eq!(
                after_outbox[index], before_outbox[index],
                "outbox immutable {name}"
            );
        }
    }
    assert_eq!(before_outbox[column(&outbox_columns, "state")], "1");
    assert_eq!(after_outbox[column(&outbox_columns, "state")], "2");
    assert_eq!(
        before_outbox[column(&outbox_columns, "receipt_digest")],
        "NULL"
    );
    assert!(after_outbox[column(&outbox_columns, "receipt_digest")].starts_with("X'"));
    assert_eq!(before_outbox[column(&outbox_columns, "applied_at")], "NULL");
    assert_ne!(after_outbox[column(&outbox_columns, "applied_at")], "NULL");

    let before_dispatch = dispatch_row_for_state(before, path, 4);
    let after_dispatch = dispatch_row_for_state(after, path, 5);
    for (index, name) in dispatch_columns.iter().enumerate() {
        if name != "state" {
            assert_eq!(
                after_dispatch[index], before_dispatch[index],
                "dispatch immutable {name}"
            );
        }
    }
    assert_eq!(before_dispatch[column(&dispatch_columns, "state")], "4");
    assert_eq!(after_dispatch[column(&dispatch_columns, "state")], "5");

    let event_columns = table_columns(path, "events");
    let before_events = &before["events"];
    let after_events = &after["events"];
    assert!(after_events.starts_with(before_events));
    assert_eq!(after_events.len(), before_events.len() + 2);
    let global = column(&event_columns, "global_position");
    let command = column(&event_columns, "command_id");
    let event_aggregate_type = column(&event_columns, "aggregate_type");
    let event_aggregate_id = column(&event_columns, "aggregate_id");
    let event_id = column(&event_columns, "event_id");
    let timestamp = column(&event_columns, "timestamp");
    let expected_position = before_events.last().unwrap()[global]
        .parse::<u64>()
        .unwrap()
        + 1;
    let expected_command = blob(command_id.as_bytes());
    let expected_aggregates = [
        ("1", blob(started.taskrun_id.as_bytes())),
        ("2", blob(started.conversation_id.as_bytes())),
    ];
    for expected in &expected_aggregates {
        assert_eq!(
            after_events[before_events.len()..]
                .iter()
                .filter(|event| {
                    event[event_aggregate_type] == expected.0
                        && event[event_aggregate_id] == expected.1
                })
                .count(),
            1,
            "expected exactly one appended event per aggregate"
        );
    }
    for (offset, event) in after_events[before_events.len()..].iter().enumerate() {
        assert_eq!(
            event[global].parse::<u64>().unwrap(),
            expected_position + offset as u64
        );
        assert_eq!(event[command], expected_command);
        assert!(expected_aggregates.contains(&(
            event[event_aggregate_type].as_str(),
            event[event_aggregate_id].clone()
        )));
    }

    let receipt_columns = table_columns(path, "command_receipts");
    let command_column = column(&receipt_columns, "command_id");
    let expected_command = blob(command_id.as_bytes());
    let before_receipts = &before["command_receipts"];
    let after_receipts = &after["command_receipts"];
    assert_eq!(after_receipts.len(), before_receipts.len());
    assert_eq!(
        before_receipts
            .iter()
            .filter(|row| row[command_column] == expected_command)
            .count(),
        1
    );
    for row in before_receipts {
        if row[command_column] != expected_command {
            assert!(
                after_receipts.contains(row),
                "unrelated command receipt changed"
            );
        }
    }
    assert_eq!(
        after_receipts
            .iter()
            .filter(|row| row[command_column] == expected_command)
            .count(),
        1
    );

    let aggregate_columns = table_columns(path, "aggregate_streams");
    let version = column(&aggregate_columns, "current_version");
    let aggregate_type = column(&aggregate_columns, "aggregate_type");
    let aggregate_id = column(&aggregate_columns, "aggregate_id");
    let last_event_id = column(&aggregate_columns, "last_event_id");
    let last_timestamp = column(&aggregate_columns, "last_timestamp");
    assert_eq!(before["aggregate_streams"].len(), expected_aggregates.len());
    assert_eq!(after["aggregate_streams"].len(), expected_aggregates.len());
    for expected in &expected_aggregates {
        assert_eq!(
            before["aggregate_streams"]
                .iter()
                .filter(|row| row[aggregate_type] == expected.0 && row[aggregate_id] == expected.1)
                .count(),
            1,
            "unexpected aggregate key before recovery"
        );
        assert_eq!(
            after["aggregate_streams"]
                .iter()
                .filter(|row| row[aggregate_type] == expected.0 && row[aggregate_id] == expected.1)
                .count(),
            1,
            "unexpected aggregate key after recovery"
        );
    }
    for expected in &expected_aggregates {
        let before = before["aggregate_streams"]
            .iter()
            .find(|row| row[aggregate_type] == expected.0 && row[aggregate_id] == expected.1)
            .unwrap();
        let after = after["aggregate_streams"]
            .iter()
            .find(|row| row[aggregate_type] == expected.0 && row[aggregate_id] == expected.1)
            .unwrap();
        let event = after_events[before_events.len()..]
            .iter()
            .find(|row| {
                row[event_aggregate_type] == expected.0 && row[event_aggregate_id] == expected.1
            })
            .unwrap();
        for (index, name) in aggregate_columns.iter().enumerate() {
            if !["current_version", "last_event_id", "last_timestamp"].contains(&name.as_str()) {
                assert_eq!(after[index], before[index], "aggregate immutable {name}");
            }
        }
        assert_eq!(
            after[version].parse::<u64>().unwrap(),
            before[version].parse::<u64>().unwrap() + 1
        );
        assert_eq!(after[last_event_id], event[event_id]);
        assert_eq!(after[last_timestamp], event[timestamp]);
    }
    super::projection_snapshot::assert_refreshed(before, after, path);
    let state_columns = table_columns(path, "event_log_state");
    let position = column(&state_columns, "next_global_position");
    let before_state = singleton_row(before, "event_log_state");
    let after_state = singleton_row(after, "event_log_state");
    for (index, name) in state_columns.iter().enumerate() {
        if name != "next_global_position" {
            assert_eq!(
                after_state[index], before_state[index],
                "event state immutable {name}"
            );
        }
    }
    assert_eq!(
        after_state[position].parse::<u64>().unwrap(),
        before_state[position].parse::<u64>().unwrap() + 2
    );
}

pub(super) fn assert_authority_renewal(
    before: &Snapshot,
    after: &Snapshot,
    path: &str,
    generation: u64,
) {
    let columns = table_columns(path, "provider_runtime_authority_state");
    let before = singleton_row(before, "provider_runtime_authority_state");
    let after = singleton_row(after, "provider_runtime_authority_state");
    let renewable = [
        "expected_generation",
        "lease_generation",
        "expected_fencing_token",
        "lease_fencing_token",
        "capability_expires_at",
        "approval_expires_at",
        "lease_expires_at",
        "state_revision",
    ];
    for (index, name) in columns.iter().enumerate() {
        if !renewable.contains(&name.as_str()) {
            assert_eq!(after[index], before[index], "authority immutable {name}");
        }
    }
    for name in [
        "expected_generation",
        "lease_generation",
        "expected_fencing_token",
        "lease_fencing_token",
    ] {
        assert_eq!(after[column(&columns, name)], generation.to_string());
    }
    let revision = column(&columns, "state_revision");
    assert_eq!(
        after[revision].parse::<u64>().unwrap(),
        before[revision].parse::<u64>().unwrap() + 1
    );
}
