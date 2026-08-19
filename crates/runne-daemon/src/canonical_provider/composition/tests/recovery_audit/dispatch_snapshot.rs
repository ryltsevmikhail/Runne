use super::fixture::*;

pub(super) fn dispatch_row_for_state<'a>(
    snapshot: &'a Snapshot,
    harness: &Harness,
    state: i64,
) -> &'a Vec<String> {
    let columns = table_columns(harness, "provider_dispatch_attempts");
    let state_column = columns.iter().position(|column| column == "state").unwrap();
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
