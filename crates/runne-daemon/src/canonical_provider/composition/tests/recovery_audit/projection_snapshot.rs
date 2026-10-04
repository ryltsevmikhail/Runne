use super::fixture::*;

fn column(columns: &[String], name: &str) -> usize {
    columns.iter().position(|column| column == name).unwrap()
}

pub(super) fn assert_refreshed(
    before: &Snapshot,
    after: &Snapshot,
    harness: &Harness,
    expected_aggregates: &[(String, String)],
) {
    assert_refreshed_streams(before, after, harness, expected_aggregates);
    assert_refreshed_snapshots(before, after, harness, expected_aggregates);
}

fn assert_refreshed_streams(
    before: &Snapshot,
    after: &Snapshot,
    harness: &Harness,
    expected_aggregates: &[(String, String)],
) {
    let columns = table_columns(harness, "aggregate_streams");
    let kind = column(&columns, "aggregate_type");
    let id = column(&columns, "aggregate_id");
    let version = column(&columns, "current_version");
    let last_event = column(&columns, "last_event_id");
    let last_timestamp = column(&columns, "last_timestamp");
    assert_eq!(
        before["aggregate_streams"].len(),
        after["aggregate_streams"].len()
    );
    for old in &before["aggregate_streams"] {
        let key = (old[kind].clone(), old[id].clone());
        let new = after["aggregate_streams"]
            .iter()
            .find(|row| row[kind] == key.0 && row[id] == key.1)
            .expect("aggregate remains present after recovery");
        if expected_aggregates.contains(&key) {
            assert_eq!(
                new[version].parse::<u64>().unwrap(),
                old[version].parse::<u64>().unwrap() + 1
            );
            for (index, name) in columns.iter().enumerate() {
                if !["current_version", "last_event_id", "last_timestamp"].contains(&name.as_str())
                {
                    assert_eq!(new[index], old[index], "aggregate immutable {name}");
                }
            }
            let event_columns = table_columns(harness, "events");
            let event_kind = column(&event_columns, "aggregate_type");
            let event_aggregate = column(&event_columns, "aggregate_id");
            let event_id = column(&event_columns, "event_id");
            let event_timestamp = column(&event_columns, "timestamp");
            let event = after["events"]
                .iter()
                .find(|event| {
                    event[event_kind] == key.0
                        && event[event_aggregate] == key.1
                        && event[event_id] == new[last_event]
                })
                .unwrap();
            assert_eq!(new[last_event], event[event_id]);
            assert_eq!(new[last_timestamp], event[event_timestamp]);
        } else {
            assert_eq!(new, old, "unrelated aggregate changed");
        }
    }
    for key in expected_aggregates {
        assert_eq!(
            before["aggregate_streams"]
                .iter()
                .filter(|row| row[kind] == key.0 && row[id] == key.1)
                .count(),
            1,
            "expected aggregate exists before recovery"
        );
        assert_eq!(
            after["aggregate_streams"]
                .iter()
                .filter(|row| row[kind] == key.0 && row[id] == key.1)
                .count(),
            1,
            "expected aggregate exists after recovery"
        );
    }
}

fn assert_refreshed_snapshots(
    before: &Snapshot,
    after: &Snapshot,
    harness: &Harness,
    expected_aggregates: &[(String, String)],
) {
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

    assert_eq!(
        before["aggregate_state_snapshots"].len(),
        after["aggregate_state_snapshots"].len()
    );
    for before_row in &before["aggregate_state_snapshots"] {
        let key = (
            before_row[aggregate_type].clone(),
            before_row[aggregate_id].clone(),
        );
        let after_row = after["aggregate_state_snapshots"]
            .iter()
            .find(|row| row[aggregate_type] == key.0 && row[aggregate_id] == key.1)
            .unwrap();
        if !expected_aggregates.contains(&key) {
            assert_eq!(
                after_row, before_row,
                "unrelated aggregate snapshot changed"
            );
            continue;
        }
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
    for key in expected_aggregates {
        assert_eq!(
            before["aggregate_state_snapshots"]
                .iter()
                .filter(|row| row[aggregate_type] == key.0 && row[aggregate_id] == key.1)
                .count(),
            1,
            "expected snapshot exists before recovery"
        );
        assert_eq!(
            after["aggregate_state_snapshots"]
                .iter()
                .filter(|row| row[aggregate_type] == key.0 && row[aggregate_id] == key.1)
                .count(),
            1,
            "expected snapshot exists after recovery"
        );
    }
}
