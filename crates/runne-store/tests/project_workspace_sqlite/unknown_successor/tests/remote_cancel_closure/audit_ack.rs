#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuditSourceSnapshot {
    pub state: i64,
    pub usage: (Option<i64>, Option<i64>, Option<i64>, Option<i64>),
    pub financial_fields: (Option<i64>, Option<String>, Option<Vec<u8>>),
    pub application_receipt: Option<Vec<u8>>,
    pub outbox_count: i64,
    pub known_ledger_count: i64,
    pub held_reservations: i64,
}

pub(super) fn source_ack_snapshot(
    fixture: &super::super::super::fixture::Fixture,
    attempt: &[u8; 16],
) -> AuditSourceSnapshot {
    fixture
        .database
        .connection()
        .query_row(
            "SELECT s.settlement_state,
                    s.input_tokens,s.output_tokens,s.cached_input_tokens,s.reasoning_output_tokens,
                    s.charge_micros,s.currency,s.settlement_digest,s.application_receipt_digest,
                    (SELECT COUNT(*) FROM provider_terminal_outbox o WHERE o.dispatch_attempt_id=s.dispatch_attempt_id),
                    (SELECT COUNT(*) FROM provider_accounting_settlements f WHERE f.dispatch_attempt_id=s.dispatch_attempt_id),
                    (SELECT COUNT(*) FROM provider_budget_reservations b
                     JOIN provider_dispatch_attempts d ON d.provider_idempotency_key=b.provider_idempotency_key
                     WHERE d.attempt_id=s.dispatch_attempt_id AND b.state=1 AND b.settled_amount IS NULL AND b.released_at IS NULL)
             FROM provider_remote_terminal_settlements s
             WHERE s.dispatch_attempt_id=?1",
            [attempt.as_slice()],
            |row| Ok(AuditSourceSnapshot {
                state: row.get(0)?,
                usage: (row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?),
                financial_fields: (row.get(5)?, row.get(6)?, row.get(7)?),
                application_receipt: row.get(8)?,
                outbox_count: row.get(9)?,
                known_ledger_count: row.get(10)?,
                held_reservations: row.get(11)?,
            }),
        )
        .unwrap()
}
