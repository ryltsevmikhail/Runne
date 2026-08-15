use super::fixture::*;

fn column(columns: &[String], name: &str) -> usize {
    columns.iter().position(|column| column == name).unwrap()
}

pub(super) fn assert_refreshed(before: &Snapshot, after: &Snapshot, harness: &Harness) {
    let snapshot_columns = table_columns(harness, "aggregate_state_snapshots");
    let event_columns = table_columns(harness, "events");
    let aggregate_type = column(&snapshot_columns, "aggregate_type");
    let aggregate_id = column(&snapshot_columns, "aggregate_id");
    let version = column(&snapshot_columns, "aggregate_version");
    let sequence = column(&snapshot_columns, "event_sequence");
    let head_event = column(&snapshot_columns, "head_event_id");
    let head_integrity = column(&snapshot_columns, "head_integrity_digest");
    let head_position = column(&snapshot_columns, "head_global_position");
    let event_type = column(&event_columns, "aggregate_type");
    let event_aggregate = column(&event_columns, "aggregate_id");
    let event_id = column(&event_columns, "event_id");
    let event_sequence = column(&event_columns, "sequence");
    let event_integrity = column(&event_columns, "integrity_digest");
    let event_position = column(&event_columns, "global_position");

    assert_eq!(before["aggregate_state_snapshots"].len(), 2);
    assert_eq!(after["aggregate_state_snapshots"].len(), 2);
    for after_row in &after["aggregate_state_snapshots"] {
        let before_row = before["aggregate_state_snapshots"]
            .iter()
            .find(|row| {
                row[aggregate_type] == after_row[aggregate_type]
                    && row[aggregate_id] == after_row[aggregate_id]
            })
            .unwrap();
        let head = after["events"]
            .iter()
            .find(|event| {
                event[event_type] == after_row[aggregate_type]
                    && event[event_aggregate] == after_row[aggregate_id]
                    && event[event_id] == after_row[head_event]
            })
            .unwrap();
        assert_eq!(
            after_row[version].parse::<u64>().unwrap(),
            before_row[version].parse::<u64>().unwrap() + 1
        );
        assert_eq!(after_row[sequence], after_row[version]);
        assert_eq!(after_row[sequence], head[event_sequence]);
        assert_eq!(after_row[head_integrity], head[event_integrity]);
        assert_eq!(after_row[head_position], head[event_position]);
    }
}
