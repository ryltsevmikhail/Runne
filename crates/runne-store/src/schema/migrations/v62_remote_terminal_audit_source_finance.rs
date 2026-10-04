fn v62_audit_source_finance_rows_match(
    connection: &Connection,
    dispatch: Option<&[u8]>,
) -> SqliteResult<bool> {
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM provider_remote_terminal_audit_receipts a
         LEFT JOIN provider_remote_terminal_settlements s USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_terminal_artifacts t USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
         LEFT JOIN provider_accounting_settlements f USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_dispositions d USING(dispatch_attempt_id)
         LEFT JOIN provider_terminal_outbox o USING(dispatch_attempt_id)
         LEFT JOIN provider_remote_terminal_applications n USING(dispatch_attempt_id)
         LEFT JOIN provider_dispatch_attempts x ON x.attempt_id=a.dispatch_attempt_id
         LEFT JOIN provider_execution_admissions p ON p.dispatch_attempt_id=x.attempt_id
         WHERE (?1 IS NULL OR a.dispatch_attempt_id=?1)
           AND (s.dispatch_attempt_id IS NULL OR t.dispatch_attempt_id IS NULL
           OR q.dispatch_attempt_id IS NULL OR s.source_kind!=2 OR s.settlement_state NOT IN (3,5)
           OR s.taskrun_id!=a.taskrun_id OR s.taskrun_attempt_id!=a.taskrun_attempt_id
           OR s.conversation_id!=a.conversation_id OR q.taskrun_id!=a.taskrun_id
           OR q.taskrun_attempt_id!=a.taskrun_attempt_id OR q.request_digest!=a.request_digest
           OR p.taskrun_id!=a.taskrun_id OR p.execution_attempt_id!=a.taskrun_attempt_id
           OR x.attempt_id IS NULL OR p.dispatch_attempt_id IS NULL
           OR p.profile_digest!=q.profile_digest
           OR s.request_digest!=a.request_digest OR s.response_id_digest!=a.response_id_digest
           OR s.artifact_digest!=a.artifact_digest OR t.plaintext_digest!=a.artifact_digest
           OR t.response_id_digest!=a.response_id_digest OR t.disposition!=a.terminal_status
           OR s.terminal_status!=a.terminal_status OR o.dispatch_attempt_id IS NOT NULL
           OR n.dispatch_attempt_id IS NOT NULL
           OR (a.accounting_state=1 AND (a.accounting_digest IS NULL OR f.dispatch_attempt_id IS NULL
               OR p.dispatch_attempt_id IS NULL OR f.settlement_digest!=a.accounting_digest
               OR f.pricing_revision_digest!=q.pricing_revision_digest
               OR f.pricing_revision_digest!=p.pricing_revision_digest
               OR f.pricing_revision_digest!=s.pricing_revision_digest
               OR f.input_tokens IS NOT s.input_tokens OR f.output_tokens IS NOT s.output_tokens
               OR f.cached_input_tokens IS NOT s.cached_input_tokens
               OR f.reasoning_output_tokens IS NOT s.reasoning_output_tokens
               OR NOT ((x.state=4 AND x.settlement_digest=f.settlement_digest)
                    OR (x.state=6 AND x.settlement_digest IS NULL))
               OR f.charge_micros>p.max_cost_micros OR f.currency!=p.currency
               OR d.disposition IS NOT CASE a.terminal_status WHEN 1 THEN 4 WHEN 2 THEN 2 WHEN 3 THEN 3 WHEN 5 THEN 5 END
               OR (SELECT COUNT(*) FROM provider_budget_reservations b
                   JOIN provider_dispatch_attempts x ON x.provider_idempotency_key=b.provider_idempotency_key
                   WHERE x.attempt_id=a.dispatch_attempt_id AND b.state=2
                     AND ((b.dimension=1 AND b.settled_amount=f.input_tokens+f.output_tokens)
                       OR (b.dimension=2 AND b.settled_amount=f.charge_micros)))!=2))
           OR (a.accounting_state=2 AND (a.accounting_digest IS NOT NULL OR f.dispatch_attempt_id IS NOT NULL
               OR d.dispatch_attempt_id IS NOT NULL
               OR x.state NOT IN (3,6) OR x.settlement_digest IS NOT NULL
               OR (SELECT COUNT(*) FROM provider_budget_reservations b
                   JOIN provider_dispatch_attempts x ON x.provider_idempotency_key=b.provider_idempotency_key
                   WHERE x.attempt_id=a.dispatch_attempt_id AND b.state=1
                     AND b.settled_amount IS NULL)!=2)))",
        [dispatch],
        |row| row.get(0),
    )?;
    Ok(invalid == 0)
}
