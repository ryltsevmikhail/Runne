fn settled_evidence_snapshot(connection: &Connection, claim: &ProviderDispatchClaim) -> SqlSnapshot {
    let attempt = sqlite_blob_literal(claim.attempt_id.as_bytes());
    let call = sqlite_blob_literal(claim.call_id.as_bytes());
    let idempotency = format!("'{}'", claim.provider_idempotency_key);
    let authority = sqlite_blob_literal(
        &connection
            .query_row(
                "SELECT authority_id FROM provider_execution_admissions WHERE dispatch_attempt_id = ?1",
                [claim.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
    );
    let mut snapshot = sql_snapshot(connection);
    for (table, rows) in &mut snapshot.0 {
        match table.as_str() {
            "provider_budget_reservations" => rows.retain(|row| row.contains(&idempotency)),
            "provider_prepared_requests" => rows.retain(|row| row.contains(&call)),
            "provider_effect_authorities" => rows.retain(|row| row.contains(&authority)),
            "provider_dispatch_attempts"
            | "provider_execution_admissions"
            | "provider_accounting_settlements"
            | "provider_encryption_nonces"
            | "provider_stream_journal"
            | "provider_terminal_outbox" => rows.retain(|row| row.contains(&attempt)),
            _ => rows.clear(),
        }
    }
    snapshot.0.retain(|(_, rows)| !rows.is_empty());
    snapshot
}

fn sqlite_blob_literal(bytes: &[u8]) -> String {
    format!(
        "X'{}'",
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    )
}

fn authority_rotation_values(connection: &Connection) -> (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) {
    connection
        .query_row(
            "SELECT expected_generation, lease_generation, expected_fencing_token,
                    lease_fencing_token, token_budget_limit, token_budget_reserved,
                    token_budget_settled, cost_budget_limit_micros,
                    cost_budget_reserved_micros, cost_budget_settled_micros
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                ))
            },
        )
        .unwrap()
}

fn immutable_authority_snapshot(connection: &Connection) -> Vec<String> {
    let mut statement = connection
        .prepare(
            "SELECT quote(runtime_authority_id), quote(database_generation), quote(principal_id),
                    quote(owner_id), quote(scope), quote(capability_grant_id),
                    quote(capability_revision), quote(capability_allowed),
                    quote(capability_revocation_epoch), quote(capability_revocation_observed),
                    quote(approval_id), quote(approval_revision), quote(approval_allowed),
                    quote(approval_revocation_epoch), quote(approval_revocation_observed),
                    quote(profile_digest), quote(pricing_revision_digest),
                    quote(activation_binding_kind), quote(activation_binding_digest),
                    quote(token_budget_limit), quote(token_budget_reserved),
                    quote(token_budget_settled), quote(cost_budget_limit_micros),
                    quote(cost_budget_reserved_micros), quote(cost_budget_settled_micros),
                    quote(authority_ttl_seconds), quote(active)
             FROM provider_runtime_authority_state WHERE id = 1",
        )
        .unwrap();
    statement
        .query_row([], |row| {
            (0..27)
                .map(|index| row.get::<_, String>(index))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchRowSnapshot {
    columns: Vec<String>,
    values: Vec<String>,
}

fn dispatch_row_snapshot(connection: &Connection, attempt_id: runne_provider::DispatchAttemptId) -> DispatchRowSnapshot {
    let columns = connection
        .prepare("PRAGMA table_info(\"provider_dispatch_attempts\")")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let attempt = sqlite_blob_literal(attempt_id.as_bytes());
    let values = sql_table_rows(connection, "provider_dispatch_attempts")
        .into_iter()
        .find(|row| row.contains(&attempt))
        .unwrap();
    DispatchRowSnapshot { columns, values }
}

fn assert_dispatch_rotation(
    before: &DispatchRowSnapshot,
    after: &DispatchRowSnapshot,
    previous_state: i64,
    next_state: i64,
) {
    assert_eq!(after.columns, before.columns);
    let state_index = before
        .columns
        .iter()
        .position(|column| column == "state")
        .unwrap();
    assert_eq!(before.values[state_index], previous_state.to_string());
    assert_eq!(after.values[state_index], next_state.to_string());
    let mut expected = before.values.clone();
    expected[state_index] = next_state.to_string();
    assert_eq!(after.values, expected);
}

#[test]
fn rotation_preserves_settled_bindings_and_freezes_stale_incomplete() {
    let (database, settled_request, _record) = setup("recovery-rotation-preserves", 11);
    let settled_claim = online_claim(&database, &settled_request, 11);
    let terminal = terminal_request_for_claim(&database, &settled_claim, 11);
    let execution = database.execution();
    execution.commit_terminal(&terminal).unwrap();
    let outbox_id = execution.pending_terminal_outbox().unwrap()[0].outbox_id;
    execution.acknowledge_terminal_outbox(outbox_id, [123; 32]).unwrap();

    let (dispatching_request, _) = prepared_request(&database, 12);
    let dispatching_claim = online_pending_claim(&database, &dispatching_request, 12);
    let (streaming_request, _) = prepared_request(&database, 13);
    let streaming_claim = online_claim(&database, &streaming_request, 13);
    assert_eq!(dispatch_state(&database, &dispatching_claim), ProviderDispatchState::Dispatching);
    assert_eq!(dispatch_state(&database, &streaming_claim), ProviderDispatchState::Streaming);
    let before = database.query_connection();
    let settled_before = settled_evidence_snapshot(&before, &settled_claim);
    let authority_rows_before = sql_table_rows(&before, "provider_runtime_authority_state");
    let authority_values_before = authority_rotation_values(&before);
    let immutable_authority_before = immutable_authority_snapshot(&before);
    let reservations_before = sql_table_rows(&before, "provider_budget_reservations");
    let effect_starts_before = sql_table_rows(&before, "provider_effect_starts");
    let settled_dispatch_before = dispatch_row_snapshot(&before, settled_claim.attempt_id);
    let dispatching_before = dispatch_row_snapshot(&before, dispatching_claim.attempt_id);
    let streaming_before = dispatch_row_snapshot(&before, streaming_claim.attempt_id);
    let utilization_before = execution.utilization().unwrap();
    assert_eq!(effect_starts_before.len(), 3);
    assert_eq!(table_count(&before, "provider_dispatch_attempts"), 3);
    drop(before);

    let rotated = rotated_runtime_config();
    database
        .execution()
        .install_runtime_authority_and_advance_worker_lease(&rotated)
        .unwrap();
    // Rotation may renew authority/lease fields and freeze only stale incomplete attempts.
    assert_eq!(dispatch_state(&database, &settled_claim), ProviderDispatchState::Settled);
    assert_eq!(
        dispatch_state(&database, &dispatching_claim),
        ProviderDispatchState::Uncertain
    );
    assert_eq!(
        dispatch_state(&database, &streaming_claim),
        ProviderDispatchState::Uncertain
    );
    let after = database.query_connection();
    let authority_rows_after = sql_table_rows(&after, "provider_runtime_authority_state");
    let authority_values_after = authority_rotation_values(&after);
    assert_ne!(authority_rows_after, authority_rows_before);
    assert_eq!(immutable_authority_snapshot(&after), immutable_authority_before);
    assert_eq!(
        authority_values_after.0,
        i64::try_from(rotated.generation).unwrap()
    );
    assert_eq!(
        authority_values_after.1,
        i64::try_from(rotated.generation).unwrap()
    );
    assert_eq!(
        authority_values_after.2,
        i64::try_from(rotated.fencing_token).unwrap()
    );
    assert_eq!(
        authority_values_after.3,
        i64::try_from(rotated.fencing_token).unwrap()
    );
    assert_eq!(
        (
            authority_values_after.4,
            authority_values_after.5,
            authority_values_after.6,
            authority_values_after.7,
            authority_values_after.8,
            authority_values_after.9,
        ),
        (
            authority_values_before.4,
            authority_values_before.5,
            authority_values_before.6,
            authority_values_before.7,
            authority_values_before.8,
            authority_values_before.9,
        )
    );
    assert_eq!(settled_evidence_snapshot(&after, &settled_claim), settled_before);
    assert_dispatch_rotation(
        &settled_dispatch_before,
        &dispatch_row_snapshot(&after, settled_claim.attempt_id),
        5,
        5,
    );
    assert_dispatch_rotation(
        &dispatching_before,
        &dispatch_row_snapshot(&after, dispatching_claim.attempt_id),
        1,
        6,
    );
    assert_dispatch_rotation(
        &streaming_before,
        &dispatch_row_snapshot(&after, streaming_claim.attempt_id),
        3,
        6,
    );
    assert_eq!(
        sql_table_rows(&after, "provider_budget_reservations"),
        reservations_before
    );
    assert_eq!(sql_table_rows(&after, "provider_effect_starts"), effect_starts_before);
    assert_eq!(table_count(&after, "provider_dispatch_attempts"), 3);
    assert_eq!(execution.utilization().unwrap(), utilization_before);
}
