use super::support::Prepared;

type ReservationSnapshot = Vec<(Vec<u8>, i64, i64, i64, Option<i64>, Option<i64>)>;
type AccountingSnapshot = (Vec<u8>, i64, i64, i64, i64, i64, String, Vec<u8>, i64);

pub(super) fn assert_ack_state(prepared: &Prepared) {
    let state: (i64, i64) = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT settlement_state,
                    (SELECT state FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1)
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, (4, 2));
}

pub(super) fn application_cardinality(prepared: &Prepared) -> (i64, i64, i64, i64, i64) {
    prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1),
                    (SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?2 AND fence=?3 AND state='released'),
                    (SELECT COUNT(*) FROM provider_budget_reservations b
                     JOIN provider_dispatch_attempts p ON p.provider_idempotency_key=b.provider_idempotency_key
                     WHERE p.attempt_id=?1)",
            rusqlite::params![
                prepared.attempt.as_bytes().as_slice(),
                prepared.fixture.taskrun_id.as_bytes().as_slice(),
                i64::try_from(prepared.fixture.claim_identity.fence.0).unwrap()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap()
}

pub(super) fn accounting_snapshot(prepared: &Prepared) -> AccountingSnapshot {
    prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT pricing_revision_digest,input_tokens,output_tokens,cached_input_tokens,
                    reasoning_output_tokens,charge_micros,currency,settlement_digest,committed_at
             FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
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
                ))
            },
        )
        .unwrap()
}

pub(super) fn reservation_snapshot(prepared: &Prepared) -> ReservationSnapshot {
    let connection = prepared.fixture.database.connection();
    let original_ids: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT token_reservation_id,cost_reservation_id
             FROM provider_dispatch_attempts WHERE attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut statement = connection
        .prepare(
            "SELECT reservation_id,dimension,amount,state,settled_amount,released_at
             FROM provider_budget_reservations
             WHERE provider_idempotency_key=(
                 SELECT provider_idempotency_key FROM provider_dispatch_attempts WHERE attempt_id=?1
             ) ORDER BY dimension",
        )
        .unwrap();
    let rows = statement
        .query_map([prepared.attempt.as_bytes().as_slice()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, original_ids.0);
    assert_eq!(rows[0].1, 1);
    assert_eq!(rows[0].3, 2);
    assert_eq!(rows[0].4, Some(7));
    assert!(rows[0].2 >= 7);
    assert!(rows[0].5.is_some());
    assert_eq!(rows[1].0, original_ids.1);
    assert_eq!(rows[1].1, 2);
    assert_eq!(rows[1].3, 2);
    assert_eq!(rows[1].4, Some(10));
    assert!(rows[1].2 >= 10);
    assert!(rows[1].5.is_some());
    rows
}

pub(super) fn assert_reservations_settled(prepared: &Prepared) {
    let _ = reservation_snapshot(prepared);
}
