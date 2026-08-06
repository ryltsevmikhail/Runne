use std::collections::BTreeMap;

use gocode_provider::DispatchAttemptId;

use super::fixture::*;
use super::oracle::{
    assert_authority_renewal, assert_completed_receipt, assert_expected_terminal_recovery_delta,
};

#[tokio::test(flavor = "current_thread")]
async fn rotation_restart_applies_pre_rotation_outbox_and_freezes_stale() {
    let harness = Harness::new().await;
    let generation = harness.generation();
    let service = harness.compose().await;
    let (begin, started) = harness.begin();
    super::super::pending::create(&service, started.clone()).await;
    let issued = harness.issue_incomplete(&service, 11, false);
    let streaming = harness.issue_incomplete(&service, 12, true);
    let before = snapshot(&harness.db_path);
    let pending_terminal = dispatch_attempt_for_state(&before, &harness.db_path, 4);
    let issued = dispatch_attempt_key(issued);
    let streaming = dispatch_attempt_key(streaming);
    let utilization_before = service.execution_store.utilization().unwrap();
    drop(service);

    let composed = harness.compose_at_generation(generation + 1).await;
    let after = snapshot(&harness.db_path);

    assert_expected_terminal_recovery_delta(
        &before,
        &after,
        &harness.db_path,
        begin.command_id,
        &started,
        true,
    );
    assert_authority_renewal(&before, &after, &harness.db_path, generation + 1);
    assert_dispatch_rows(
        &before,
        &after,
        &harness.db_path,
        &[(pending_terminal, 4, 5), (issued, 1, 6), (streaming, 3, 6)],
    );
    assert_unchanged_except(
        &before,
        &after,
        &[
            "provider_terminal_outbox",
            "provider_dispatch_attempts",
            "provider_runtime_authority_state",
            "events",
            "command_receipts",
            "aggregate_streams",
            "event_log_state",
        ],
    );
    assert_eq!(
        after["provider_budget_reservations"],
        before["provider_budget_reservations"]
    );
    assert_active_reservations(&after, &harness.db_path, "rotation-incomplete-11");
    assert_active_reservations(&after, &harness.db_path, "rotation-incomplete-12");
    assert_eq!(
        composed.execution_store.utilization().unwrap(),
        utilization_before
    );
    assert_remaining(composed.execution_store.utilization().unwrap());
    let receipt = harness
        .store
        .load_text_generation_receipt_by_command(begin.command_id, &begin.idempotency_key)
        .unwrap();
    assert_completed_receipt(&receipt, &started);
    assert_eq!(
        composed
            .recovery_observation_registry()
            .snapshot_recovery_observation()
            .observed_count(),
        Some(1)
    );
}

fn assert_remaining(
    utilization: (
        gocode_application::provider::ProviderBudgetUtilization,
        gocode_application::provider::ProviderBudgetUtilization,
    ),
) {
    assert_eq!(
        utilization.0.remaining,
        utilization.0.limit - utilization.0.reserved - utilization.0.settled
    );
    assert_eq!(
        utilization.1.remaining,
        utilization.1.limit - utilization.1.reserved - utilization.1.settled
    );
}

fn dispatch_attempt_for_state(snapshot: &Snapshot, path: &str, state: i64) -> String {
    let columns = table_columns(path, "provider_dispatch_attempts");
    let attempt = column_index(&columns, "attempt_id");
    let state_index = column_index(&columns, "state");
    let rows = snapshot["provider_dispatch_attempts"]
        .iter()
        .filter(|row| row[state_index] == state.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        1,
        "unexpected dispatch state {state} cardinality"
    );
    rows[0][attempt].clone()
}

fn dispatch_attempt_key(attempt_id: DispatchAttemptId) -> String {
    format!("X'{}'", hex::encode_upper(attempt_id.as_bytes()))
}

fn assert_dispatch_rows(
    before: &Snapshot,
    after: &Snapshot,
    path: &str,
    expected: &[(String, i64, i64)],
) {
    let columns = table_columns(path, "provider_dispatch_attempts");
    let attempt = column_index(&columns, "attempt_id");
    let state = column_index(&columns, "state");
    let before = dispatch_rows_by_attempt(before, attempt);
    let after = dispatch_rows_by_attempt(after, attempt);
    assert_eq!(before.len(), after.len());
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    let expected_by_attempt = expected
        .iter()
        .map(|(attempt, before, after)| (attempt, (before, after)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(expected_by_attempt.len(), 3);
    assert!(
        expected_by_attempt
            .keys()
            .all(|attempt| before.contains_key(*attempt))
    );
    for (attempt, before_row) in before {
        let after_row = &after[&attempt];
        let Some((before_state, after_state)) = expected_by_attempt.get(&attempt) else {
            assert_eq!(
                after_row, &before_row,
                "unexpected dispatch change {attempt}"
            );
            continue;
        };
        assert_eq!(before_row[state], before_state.to_string());
        let mut expected_row = before_row;
        expected_row[state] = after_state.to_string();
        assert_eq!(
            after_row, &expected_row,
            "unexpected dispatch delta {attempt}"
        );
    }
}

fn dispatch_rows_by_attempt(snapshot: &Snapshot, attempt: usize) -> BTreeMap<String, Vec<String>> {
    snapshot["provider_dispatch_attempts"]
        .iter()
        .map(|row| (row[attempt].clone(), row.clone()))
        .collect()
}

fn column_index(columns: &[String], name: &str) -> usize {
    columns.iter().position(|column| column == name).unwrap()
}

fn assert_active_reservations(snapshot: &Snapshot, path: &str, idempotency_key: &str) {
    let state = table_columns(path, "provider_budget_reservations")
        .iter()
        .position(|column| column == "state")
        .unwrap();
    let rows = snapshot["provider_budget_reservations"]
        .iter()
        .filter(|row| row.contains(&format!("'{idempotency_key}'")))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row[state] == "1"));
}
