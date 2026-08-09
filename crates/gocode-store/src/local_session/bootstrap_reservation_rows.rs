use gocode_application::local_session::{
    BootstrapReservationError, BootstrapReservationState, LocalSessionChallengeId,
    PreallocateReservation, Reservation,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn validate_preallocation(
    input: &PreallocateReservation,
) -> Result<(), BootstrapReservationError> {
    if input.key_version != 1
        || input.client_nonce == [0; 32]
        || input.binding_proof == [0; 32]
        || input.not_before_rfc3339_utc_microseconds.len() != 27
        || input.expiry_rfc3339_utc_microseconds.len() != 27
        || input.not_before_unix_microseconds < 0
        || input.observed_at_unix_microseconds < input.not_before_unix_microseconds
        || input.observed_at_unix_microseconds >= input.expiry_unix_microseconds
        || input.fence == 0
    {
        return Err(BootstrapReservationError::Rejected);
    }
    Ok(())
}

pub(super) fn observe_clock_tx(
    tx: &Transaction<'_>,
    now: i64,
) -> Result<(), BootstrapReservationError> {
    let observed: i64 = tx
        .query_row(
            "SELECT observed_at FROM bootstrap_last_observed_clock WHERE id=1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if now < observed {
        return Err(BootstrapReservationError::ClockRegression);
    }
    tx.execute(
        "UPDATE bootstrap_last_observed_clock SET observed_at=?1 WHERE id=1",
        [now],
    )
    .map_err(storage)?;
    Ok(())
}

pub(super) fn prune_expired(
    tx: &Transaction<'_>,
    now: i64,
) -> Result<(), BootstrapReservationError> {
    tx.execute(
        "DELETE FROM bootstrap_reservation_tombstones WHERE expiry_unix_microseconds <= ?1",
        [now],
    )
    .map_err(storage)?;
    tx.execute(
        "DELETE FROM bootstrap_reservations WHERE expiry_unix_microseconds <= ?1",
        [now],
    )
    .map_err(storage)?;
    Ok(())
}

pub(super) fn exact_replay(existing: &Reservation, input: &PreallocateReservation) -> bool {
    existing.binding_proof == input.binding_proof
        && existing.key_version == input.key_version
        && existing.client_nonce == input.client_nonce
        && existing.not_before_rfc3339_utc_microseconds == input.not_before_rfc3339_utc_microseconds
        && existing.expiry_rfc3339_utc_microseconds == input.expiry_rfc3339_utc_microseconds
        && existing.not_before_unix_microseconds == input.not_before_unix_microseconds
        && existing.expiry_unix_microseconds == input.expiry_unix_microseconds
        && existing.fence == input.fence
}

pub(super) fn record_failed_attempt(
    tx: &Transaction<'_>,
    reservation: &Reservation,
) -> Result<(), BootstrapReservationError> {
    let attempts = reservation
        .attempt_count
        .saturating_add(1)
        .min(gocode_application::local_session::MAX_BOOTSTRAP_FINAL_ATTEMPTS);
    let state = if attempts == gocode_application::local_session::MAX_BOOTSTRAP_FINAL_ATTEMPTS {
        "FENCED"
    } else {
        "RESERVED"
    };
    tx.execute(
        "UPDATE bootstrap_reservations SET attempt_count=?2, reservation_state=?3
         WHERE reservation_key=?1 AND reservation_state='RESERVED'",
        params![
            reservation.reservation_key.as_slice(),
            i64::from(attempts),
            state,
        ],
    )
    .map_err(storage)?;
    Ok(())
}

pub(super) fn load_by_key(
    tx: &Transaction<'_>,
    key: &[u8; 32],
) -> Result<Option<Reservation>, BootstrapReservationError> {
    load(tx, "reservation_key", key)
}

pub(super) fn load_by_challenge(
    tx: &Transaction<'_>,
    challenge: &LocalSessionChallengeId,
) -> Result<Option<Reservation>, BootstrapReservationError> {
    load(tx, "challenge_id", &challenge.0)
}

fn load(
    tx: &Transaction<'_>,
    column: &str,
    value: &[u8],
) -> Result<Option<Reservation>, BootstrapReservationError> {
    let sql = format!(
        "SELECT reservation_key, challenge_id, server_nonce, binding_proof, key_version,
                client_nonce, not_before_rfc3339_utc_microseconds,
                expiry_rfc3339_utc_microseconds, not_before_unix_microseconds,
                expiry_unix_microseconds, attempt_count, fence, reservation_state
         FROM bootstrap_reservations WHERE {column}=?1"
    );
    tx.query_row(&sql, [value], decode_reservation)
        .optional()
        .map_err(storage)
}

fn decode_reservation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Reservation> {
    let state = match row.get::<_, String>(12)?.as_str() {
        "RESERVED" => BootstrapReservationState::Reserved,
        "CONSUMED" => BootstrapReservationState::Consumed,
        "FENCED" => BootstrapReservationState::Fenced,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(Reservation {
        reservation_key: fixed(row.get(0)?)?,
        challenge_id: LocalSessionChallengeId(fixed(row.get(1)?)?),
        server_nonce: fixed(row.get(2)?)?,
        binding_proof: fixed(row.get(3)?)?,
        key_version: u16::try_from(row.get::<_, i64>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_nonce: fixed(row.get(5)?)?,
        not_before_rfc3339_utc_microseconds: row.get(6)?,
        expiry_rfc3339_utc_microseconds: row.get(7)?,
        not_before_unix_microseconds: row.get(8)?,
        expiry_unix_microseconds: row.get(9)?,
        attempt_count: u16::try_from(row.get::<_, i64>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        fence: u64::try_from(row.get::<_, i64>(11)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        state,
    })
}

fn fixed<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(super) fn storage(_: rusqlite::Error) -> BootstrapReservationError {
    BootstrapReservationError::Storage
}
