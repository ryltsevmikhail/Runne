include!("remote_terminal_effects_snapshot_d2_types.rs");
fn d2_latest_remote_dispatch(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<Option<[u8; 16]>, ProviderExecutionError> {
    let budget_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2)",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !budget_exists {
        return Ok(None);
    }
    let mut statement = tx
        .prepare(
            "SELECT b.round_index,b.attempt_id,b.node_id,b.node_epoch,
                    b.original_claim_version,b.fence,b.call_id,b.prepared_digest,
                    b.render_digest,b.profile_digest,b.provider_idempotency_key,
                    b.previous_attempt_id,b.previous_cycle_id,b.previous_proposal_index,
                    b.previous_semantic_digest,b.previous_result_digest,
                    a.taskrun_id,a.execution_attempt_id,a.prepared_digest,a.render_digest,
                    a.profile_digest,a.provider_idempotency_key,a.dispatch_attempt_id,
                    d.call_id,d.state,k.application_kind,o.state
             FROM taskrun_provider_round_bindings b
             LEFT JOIN provider_execution_admissions a ON a.call_id=b.call_id
             LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
             LEFT JOIN provider_terminal_application_kinds k
               ON k.dispatch_attempt_id=d.attempt_id AND k.outbox_id=(
                 SELECT o2.outbox_id FROM provider_terminal_outbox o2
                 WHERE o2.dispatch_attempt_id=d.attempt_id AND o2.state=1
                 ORDER BY o2.outbox_id LIMIT 1)
             LEFT JOIN provider_terminal_outbox o
               ON o.dispatch_attempt_id=d.attempt_id AND o.state=1
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2 ORDER BY b.round_index",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map(
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                ))
            },
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        .collect::<Result<Vec<D2RemoteRoundRow>, _>>()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    drop(statement);
    let coding =
        crate::store::taskrun_tool_invocation::budget_policy::coding_origin(tx, taskrun_id)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    crate::store::taskrun_tool_invocation::budget_policy::verify_origin_policy(tx, taskrun_id)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if coding && rows.is_empty() {
        let admitted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2)",params![taskrun_id.as_bytes(),attempt_id.as_bytes()],|r|r.get(0)).map_err(|_|ProviderExecutionError::StoreUnavailable)?;
        return if admitted {
            Err(ProviderExecutionError::JournalCorrupt)
        } else {
            Ok(None)
        };
    }
    if rows.len() < if coding { 1 } else { 2 } || rows.len() > if coding { 33 } else { 3 } {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let first = &rows[0];
    if first.0 != 0 || first.1.as_slice() != attempt_id.as_bytes() {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let budget_node = uuid::Uuid::from_slice(&first.2)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .to_string();
    let budget_matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets
             WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4
               AND node_epoch=?5 AND policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1'))",
            params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                first.5,
                budget_node,
                first.3
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !budget_matches {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let same_claim: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4
               AND node_epoch=?5 AND new_version=?6)",
            params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                first.5,
                first.2,
                first.3,
                first.4
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !same_claim {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let unbound_admission: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
             WHERE a.taskrun_id=?1 AND a.execution_attempt_id=?2 AND NOT EXISTS(
               SELECT 1 FROM taskrun_provider_round_bindings b
               WHERE b.taskrun_id=a.taskrun_id AND b.attempt_id=a.execution_attempt_id
                 AND b.call_id=a.call_id))",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let intent_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM provider_remote_request_intents
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if unbound_admission || intent_count != rows.len() as i64 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let last_index =
        i64::try_from(rows.len() - 1).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    for (position, row) in rows.iter().enumerate() {
        let index = i64::try_from(position).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        if row.0 != index
            || row.1 != first.1
            || row.2 != first.2
            || row.3 != first.3
            || row.4 != first.4
            || row.5 != first.5
            || row.9 != first.9
            || row.16.as_deref() != Some(taskrun_id.as_bytes().as_slice())
            || row.17.as_deref() != Some(attempt_id.as_bytes().as_slice())
            || row.18.as_deref() != Some(row.7.as_slice())
            || row.19.as_deref() != Some(row.8.as_slice())
            || row.20.as_deref() != Some(row.9.as_slice())
            || row.21.as_deref() != Some(row.10.as_str())
            || row.22.is_none()
            || row.23.as_deref() != Some(row.6.as_slice())
        {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let intent_matches: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents
                 WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3)",
                params![
                    row.22.as_deref(),
                    taskrun_id.as_bytes(),
                    attempt_id.as_bytes()
                ],
                |result| result.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if !intent_matches {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        if index == 0 {
            if (
                row.11.is_some(),
                row.12.is_some(),
                row.13.is_some(),
                row.14.is_some(),
                row.15.is_some(),
            ) != (false, false, false, false, false)
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
        } else {
            let prior: PriorD2ToolResultRef<'_> = (
                row.11.as_deref(),
                row.12.as_deref(),
                row.13,
                row.14.as_deref(),
                row.15.as_deref(),
            );
            let (
                Some(prior_attempt),
                Some(prior_cycle),
                Some(prior_index),
                Some(prior_semantic),
                Some(prior_result),
            ) = prior
            else {
                return Err(ProviderExecutionError::JournalCorrupt);
            };
            if prior_attempt != attempt_id.as_bytes() || (!coding && prior_index != index - 1) {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
            let prior_result_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations
                     WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3
                       AND proposal_index=?4 AND semantic_digest=?5 AND result_digest=?6 AND round_index=?7
                       AND state='result' AND result_truncated=0 AND continuation_started=1
                       AND local_stop_state=2 AND managed_area_identity=empty_proof_identity)",
                    params![
                        taskrun_id.as_bytes(),
                        prior_attempt,
                        prior_cycle,
                        prior_index,
                        prior_semantic,
                        prior_result, index-1
                    ],
                    |result| result.get(0),
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            if !prior_result_exists {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
        }
        if index < last_index && (row.24 != Some(4) || row.25 != Some(2) || row.26 != Some(1)) {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
    }
    let dispatch: [u8; 16] = rows
        .last()
        .and_then(|row| row.22.as_deref())
        .ok_or(ProviderExecutionError::JournalCorrupt)?
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    Ok(Some(dispatch))
}
