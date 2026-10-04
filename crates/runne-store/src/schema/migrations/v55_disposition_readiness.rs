type V55SuccessorReleaseRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

fn v55_disposition_objects_match(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_terminal_dispositions'", [], |row| row.get(0),
    ).optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(V55_DISPOSITION_DDL)) {
        return Ok(false);
    }
    for (name, expected) in V55_DISPOSITION_TRIGGERS {
        if !schema_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    let version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version),0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    let query = match version {
        61.. => v61_disposition_readiness_sql(),
        59..=60 => V59_DISPOSITION_READINESS_SQL.to_owned(),
        _ => V55_DISPOSITION_READINESS_SQL.to_owned(),
    };
    let invalid: i64 = connection.query_row(&query, [], |row| row.get(0))?;
    if invalid != 0 {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT dispatch_attempt_id FROM provider_terminal_dispositions WHERE disposition=6",
    )?;
    let audit_rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for attempt in audit_rows {
        if !v55_audit_only_cancel_fence_matches(connection, &attempt)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v61_disposition_readiness_sql() -> String {
    const OLD_JOIN: &str = "WHERE s.dispatch_attempt_id IS NULL OR a.attempt_id IS NULL OR a.settlement_digest!=s.settlement_digest";
    const OLD: &str = "OR (d.disposition IN (2,3,4,5,6) AND a.state=5 AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o\n               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id)))";
    const PENDING: &str = "EXISTS(SELECT 1 FROM provider_remote_terminal_settlements x
                 JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
                 JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
                 JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
                 WHERE x.dispatch_attempt_id=d.dispatch_attempt_id AND x.source_kind=2
                   AND x.settlement_state=3 AND x.application_receipt_digest IS NULL
                   AND x.taskrun_id=q.taskrun_id AND x.taskrun_attempt_id=q.taskrun_attempt_id
                   AND x.request_digest=q.request_digest AND x.response_id_digest=r.plaintext_digest
                   AND x.response_id_digest=t.response_id_digest AND x.artifact_digest=t.plaintext_digest
                   AND x.terminal_status=t.disposition AND x.profile_digest=q.profile_digest
                   AND x.pricing_revision_digest=q.pricing_revision_digest
                   AND x.runtime_authority_id=q.runtime_authority_id
                   AND x.database_generation=q.database_generation
                   AND x.runtime_generation=q.runtime_generation AND x.fencing_token=q.fencing_token
                   AND a.state IN (3,4,6)
                   AND d.disposition=CASE x.terminal_status
                     WHEN 1 THEN 4 WHEN 2 THEN 2 WHEN 3 THEN 3 WHEN 5 THEN 5 END
                   AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                     WHERE o.dispatch_attempt_id=a.attempt_id)
                   AND ((s.dispatch_attempt_id IS NULL AND a.settlement_digest IS NULL
                         AND (SELECT COUNT(*) FROM provider_budget_reservations b
                              WHERE b.provider_idempotency_key=a.provider_idempotency_key AND b.state=1)=2)
                     OR (s.dispatch_attempt_id IS NOT NULL
                         AND a.state IN (4,6)
                         AND ((a.state=4 AND a.settlement_digest=s.settlement_digest)
                           OR (a.state=6 AND a.settlement_digest IS NULL))
                         AND s.pricing_revision_digest=x.pricing_revision_digest
                         AND s.input_tokens IS x.input_tokens AND s.output_tokens IS x.output_tokens
                         AND s.cached_input_tokens IS x.cached_input_tokens
                         AND s.reasoning_output_tokens IS x.reasoning_output_tokens
                         AND (SELECT COUNT(*) FROM provider_budget_reservations b
                              WHERE b.provider_idempotency_key=a.provider_idempotency_key
                                AND b.state=2 AND b.released_at IS NOT NULL
                                AND ((b.dimension=1 AND b.settled_amount=s.input_tokens+s.output_tokens)
                                  OR (b.dimension=2 AND b.settled_amount=s.charge_micros)))=2)))";
    let join_replacement = format!(
        "WHERE (s.dispatch_attempt_id IS NULL AND NOT ({PENDING}))
           OR a.attempt_id IS NULL
           OR a.settlement_digest!=s.settlement_digest"
    );
    let disposition_replacement = format!(
        "OR (d.disposition IN (2,3,4,5,6) AND (
                 (a.state=5 AND NOT EXISTS(
                   SELECT 1 FROM provider_terminal_outbox o
                   WHERE o.dispatch_attempt_id=d.dispatch_attempt_id))
                 OR {PENDING})))"
    );
    V59_DISPOSITION_READINESS_SQL
        .replace(OLD_JOIN, &join_replacement)
        .replace(OLD, &disposition_replacement)
}

const V55_DISPOSITION_READINESS_SQL: &str = "SELECT COUNT(*) FROM provider_terminal_dispositions d
         LEFT JOIN provider_accounting_settlements s USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts a ON a.attempt_id=d.dispatch_attempt_id
         WHERE s.dispatch_attempt_id IS NULL OR a.attempt_id IS NULL OR a.settlement_digest!=s.settlement_digest
           OR NOT ((d.disposition=1 AND ((a.state=4 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id AND o.settlement_digest=s.settlement_digest
                 AND o.state=1 AND o.receipt_digest IS NULL AND o.applied_at IS NULL))
             OR (a.state=5 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id AND o.settlement_digest=s.settlement_digest
                 AND o.state=2 AND o.receipt_digest IS NOT NULL AND o.applied_at IS NOT NULL))))
           OR (d.disposition IN (2,3,4,5,6) AND a.state=5 AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
                 WHERE o.dispatch_attempt_id=d.dispatch_attempt_id)))
           OR (d.disposition=5 AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
               WHERE t.dispatch_attempt_id=d.dispatch_attempt_id AND t.disposition=5))
           OR (d.disposition=6 AND (NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
               WHERE t.dispatch_attempt_id=d.dispatch_attempt_id) OR EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id)))
           OR (EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t WHERE t.dispatch_attempt_id=d.dispatch_attempt_id)
                AND d.disposition NOT IN (4,6)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
                  WHERE t.dispatch_attempt_id=d.dispatch_attempt_id AND t.disposition=d.disposition))";

const V59_DISPOSITION_READINESS_SQL: &str = "SELECT COUNT(*) FROM provider_terminal_dispositions d
         LEFT JOIN provider_accounting_settlements s USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts a ON a.attempt_id=d.dispatch_attempt_id
         WHERE s.dispatch_attempt_id IS NULL OR a.attempt_id IS NULL OR a.settlement_digest!=s.settlement_digest
           OR NOT ((d.disposition=1 AND ((a.state=4 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id AND o.settlement_digest=s.settlement_digest
                 AND o.state=1 AND o.receipt_digest IS NULL AND o.applied_at IS NULL))
             OR (a.state=5 AND EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id AND o.settlement_digest=s.settlement_digest
                 AND o.state=2 AND o.receipt_digest IS NOT NULL AND o.applied_at IS NOT NULL))
             OR (a.state=6 AND EXISTS(SELECT 1 FROM provider_remote_terminal_settlements x
               JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
               JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
               WHERE x.dispatch_attempt_id=d.dispatch_attempt_id AND a.settlement_digest IS NULL
                 AND x.settlement_state IN (2,4)
                 AND x.terminal_status=1 AND x.publication_disposition=0
                 AND x.settlement_digest=s.settlement_digest AND x.input_tokens=s.input_tokens
                 AND x.output_tokens=s.output_tokens AND x.cached_input_tokens=s.cached_input_tokens
                 AND x.reasoning_output_tokens=s.reasoning_output_tokens AND x.charge_micros=s.charge_micros
                 AND x.currency=s.currency AND x.artifact_digest=t.plaintext_digest
                 AND o.terminal_sequence=0 AND o.settlement_digest=s.settlement_digest
                 AND o.key_id=t.key_id AND o.key_version=t.key_version AND o.nonce=t.nonce
                 AND o.runtime_generation=t.runtime_generation AND o.profile_digest=t.profile_digest
                 AND o.ciphertext=t.ciphertext AND o.plaintext_len=t.plaintext_len
                 AND o.plaintext_digest=t.plaintext_digest
                 AND ((x.settlement_state=2 AND o.state=1 AND o.receipt_digest IS NULL AND o.applied_at IS NULL)
                   OR (x.settlement_state=4 AND o.state=2 AND o.receipt_digest IS NOT NULL
                     AND o.receipt_digest=x.application_receipt_digest AND o.applied_at IS NOT NULL)))))
           OR (d.disposition IN (2,3,4,5,6) AND a.state=5 AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id)))
           OR (d.disposition=5 AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
               WHERE t.dispatch_attempt_id=d.dispatch_attempt_id AND t.disposition=5))
           OR (d.disposition=6 AND (NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
               WHERE t.dispatch_attempt_id=d.dispatch_attempt_id) OR EXISTS(SELECT 1 FROM provider_terminal_outbox o
               WHERE o.dispatch_attempt_id=d.dispatch_attempt_id)))
           OR (EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t WHERE t.dispatch_attempt_id=d.dispatch_attempt_id)
                AND d.disposition NOT IN (4,6)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts t
                  WHERE t.dispatch_attempt_id=d.dispatch_attempt_id AND t.disposition=d.disposition)))";

fn v55_audit_only_cancel_fence_matches(
    connection: &Connection,
    dispatch_attempt_id: &[u8],
) -> SqliteResult<bool> {
    let fence_table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='taskrun_provider_cancel_fences')",
        [],
        |row| row.get(0),
    )?;
    if fence_table {
        let fence: Option<V55SuccessorReleaseRow> = connection
        .query_row(
            "SELECT f.taskrun_id,f.taskrun_attempt_id,f.cancellation_event_id,f.cancellation_version
             FROM taskrun_provider_cancel_fences f
             JOIN provider_execution_admissions a USING(dispatch_attempt_id)
             WHERE f.dispatch_attempt_id=?1 AND f.taskrun_id=a.taskrun_id
               AND f.taskrun_attempt_id=a.execution_attempt_id",
            [dispatch_attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
        if let Some((taskrun, attempt, event, version)) = fence
            && v55_verified_attempt_event(connection, &taskrun, &attempt, &event, version, false)? {
                return Ok(true);
            }
    }
    v55_audit_only_user_supersession_matches(connection, dispatch_attempt_id)
}

fn v55_verified_attempt_event(
    connection: &Connection,
    taskrun: &[u8],
    attempt: &[u8],
    event_id: &[u8],
    version: i64,
    supersession: bool,
) -> SqliteResult<bool> {
    use crate::codec::{StoreCodec, TaskRunEventCodec};
    use runne_domain::task_run::TaskRunEvent;
    let (Ok(taskrun), Ok(attempt), Ok(event_id)) = (
        <[u8; 16]>::try_from(taskrun),
        <[u8; 16]>::try_from(attempt),
        <[u8; 16]>::try_from(event_id),
    ) else {
        return Ok(false);
    };
    let payload: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1
             AND aggregate_id=?2 AND sequence=?3",
            rusqlite::params![event_id.as_slice(), taskrun.as_slice(), version],
            |row| row.get(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(false);
    };
    let decoded: Result<runne_domain::task_run::TaskRunEvent, _> =
        StoreCodec::decode(&TaskRunEventCodec, &payload);
    let event_matches = if supersession {
        matches!(decoded, Ok(TaskRunEvent::UserSupersedeUnknown {
            predecessor_attempt_id, ..
        }) if *predecessor_attempt_id.as_bytes() == attempt)
    } else {
        matches!(decoded, Ok(TaskRunEvent::CancellationRequested))
    };
    if !event_matches || version <= 1 {
        return Ok(false);
    }
    Ok(
        crate::store::taskrun_claim::active_attempt_at_verified_version(
            connection,
            runne_domain::id::TaskRunId::from_bytes(taskrun),
            u64::try_from(version - 1).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .is_some_and(|active| *active.as_bytes() == attempt),
    )
}

fn v55_audit_only_user_supersession_matches(
    connection: &Connection,
    dispatch_attempt_id: &[u8],
) -> SqliteResult<bool> {
    let installed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
         AND name='taskrun_unknown_successor_receipts')",
        [],
        |row| row.get(0),
    )?;
    if !installed {
        return Ok(false);
    }
    let row: Option<V55SuccessorReleaseRow> = connection
        .query_row(
            "SELECT r.predecessor_taskrun_id,r.predecessor_attempt_id,
                    r.predecessor_event_id,r.predecessor_event_version
             FROM taskrun_unknown_successor_receipts r
             JOIN provider_execution_admissions a
               ON a.dispatch_attempt_id=r.predecessor_dispatch_attempt_id
             WHERE r.predecessor_dispatch_attempt_id=?1
               AND a.taskrun_id=r.predecessor_taskrun_id
               AND a.execution_attempt_id=r.predecessor_attempt_id
               AND r.predecessor_event_id IS NOT NULL
               AND r.predecessor_event_version IS NOT NULL",
            [dispatch_attempt_id],
            |saved| Ok((saved.get(0)?, saved.get(1)?, saved.get(2)?, saved.get(3)?)),
        )
        .optional()?;
    let Some((taskrun, attempt, event, version)) = row else {
        return Ok(false);
    };
    v55_verified_attempt_event(connection, &taskrun, &attempt, &event, version, true)
}
