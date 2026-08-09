use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use gocode_application::local_session::{
    BootstrapReservationError, BootstrapReservationState, BootstrapReservationStore,
    ConsumeReservation, ConsumedReservation, LocalSessionChallengeId, PreallocateReservation,
    Reservation,
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{TransactionBehavior, params};

use crate::schema::ManagedConnection;

use super::bootstrap_reservation_rows::{
    exact_replay, load_by_challenge, load_by_key, observe_clock_tx, prune_expired,
    record_failed_attempt, storage, validate_preallocation,
};

/// SQLite-backed reservation store using one factory-managed writer.
pub struct SqliteBootstrapReservationStore {
    connection: Mutex<ManagedConnection>,
    entropy_calls: Option<Arc<AtomicUsize>>,
}

impl SqliteBootstrapReservationStore {
    /// Retains an already profiled and catalog-validated managed connection.
    pub fn new(connection: ManagedConnection) -> Self {
        Self {
            connection: Mutex::new(connection),
            entropy_calls: None,
        }
    }

    /// Builds a store that counts actual OS-random fills for security tests.
    #[doc(hidden)]
    pub fn with_entropy_audit(
        connection: ManagedConnection,
        entropy_calls: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            connection: Mutex::new(connection),
            entropy_calls: Some(entropy_calls),
        }
    }
}

impl BootstrapReservationStore for SqliteBootstrapReservationStore {
    fn preallocate(
        &self,
        input: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        validate_preallocation(&input)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| BootstrapReservationError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        observe_clock_tx(&tx, input.observed_at_unix_microseconds)?;
        prune_expired(&tx, input.observed_at_unix_microseconds)?;
        if let Some(existing) = load_by_key(&tx, &input.reservation_key)? {
            if !exact_replay(&existing, &input) {
                return Err(BootstrapReservationError::Rejected);
            }
            tx.commit().map_err(storage)?;
            return Ok(existing);
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM bootstrap_reservations WHERE expiry_unix_microseconds > ?1",
                [input.observed_at_unix_microseconds],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if count
            >= i64::try_from(gocode_application::local_session::MAX_BOOTSTRAP_RESERVATIONS)
                .map_err(|_| BootstrapReservationError::Storage)?
        {
            tx.commit().map_err(storage)?;
            return Err(BootstrapReservationError::Capacity);
        }
        let (challenge_id, server_nonce) = random_challenge(self.entropy_calls.as_deref());
        tx.execute(
            "INSERT INTO bootstrap_reservations (
                reservation_key, challenge_id, server_nonce, binding_proof, key_version,
                client_nonce, not_before_rfc3339_utc_microseconds,
                expiry_rfc3339_utc_microseconds, not_before_unix_microseconds,
                expiry_unix_microseconds, reserved_at_unix_microseconds, attempt_count,
                fence, reservation_state, authority_digest, consumed_at_unix_microseconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, 'RESERVED', NULL, NULL)",
            params![
                input.reservation_key.as_slice(),
                challenge_id.0.as_slice(),
                server_nonce.as_slice(),
                input.binding_proof.as_slice(),
                i64::from(input.key_version),
                input.client_nonce.as_slice(),
                input.not_before_rfc3339_utc_microseconds,
                input.expiry_rfc3339_utc_microseconds,
                input.not_before_unix_microseconds,
                input.expiry_unix_microseconds,
                input.observed_at_unix_microseconds,
                i64::try_from(input.fence).map_err(|_| BootstrapReservationError::Rejected)?,
            ],
        )
        .map_err(storage)?;
        let reservation =
            load_by_key(&tx, &input.reservation_key)?.ok_or(BootstrapReservationError::Storage)?;
        tx.commit().map_err(storage)?;
        Ok(reservation)
    }

    fn consume_final(
        &self,
        input: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        if input.observed_at_unix_microseconds < 0 {
            return Err(BootstrapReservationError::Rejected);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| BootstrapReservationError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let Some(reservation) = load_by_challenge(&tx, &input.challenge_id)? else {
            return Err(BootstrapReservationError::Rejected);
        };
        observe_clock_tx(&tx, input.observed_at_unix_microseconds)?;
        if input.observed_at_unix_microseconds >= reservation.expiry_unix_microseconds {
            prune_expired(&tx, input.observed_at_unix_microseconds)?;
            tx.commit().map_err(storage)?;
            return Err(BootstrapReservationError::Rejected);
        }
        if reservation.state != BootstrapReservationState::Reserved {
            return Err(BootstrapReservationError::Rejected);
        }
        if reservation.binding_proof != input.binding_proof || !(input.verify)(&reservation) {
            record_failed_attempt(&tx, &reservation)?;
            tx.commit().map_err(storage)?;
            return Err(BootstrapReservationError::Rejected);
        }
        tx.execute(
            "UPDATE bootstrap_reservations
             SET reservation_state='CONSUMED', authority_digest=?2,
                 consumed_at_unix_microseconds=?3
             WHERE reservation_key=?1 AND reservation_state='RESERVED'",
            params![
                reservation.reservation_key.as_slice(),
                input.authority_digest.as_slice(),
                input.observed_at_unix_microseconds,
            ],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO bootstrap_reservation_tombstones (
                reservation_key, challenge_id, binding_proof, authority_digest,
                consumed_at_unix_microseconds, expiry_unix_microseconds, fence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                reservation.reservation_key.as_slice(),
                reservation.challenge_id.0.as_slice(),
                reservation.binding_proof.as_slice(),
                input.authority_digest.as_slice(),
                input.observed_at_unix_microseconds,
                reservation.expiry_unix_microseconds,
                i64::try_from(reservation.fence).map_err(|_| BootstrapReservationError::Storage)?,
            ],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(ConsumedReservation {
            reservation_key: reservation.reservation_key,
            challenge_id: reservation.challenge_id,
            consumed_at_unix_microseconds: input.observed_at_unix_microseconds,
            fence: reservation.fence,
        })
    }

    fn observe_clock(&self, now: i64) -> Result<i64, BootstrapReservationError> {
        if now < 0 {
            return Err(BootstrapReservationError::Rejected);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| BootstrapReservationError::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        observe_clock_tx(&tx, now)?;
        tx.commit().map_err(storage)?;
        Ok(now)
    }
}

fn random_challenge(entropy_calls: Option<&AtomicUsize>) -> (LocalSessionChallengeId, [u8; 32]) {
    let mut challenge = [0; 16];
    let mut nonce = [0; 32];
    while challenge == [0; 16] {
        fill_random(entropy_calls, &mut challenge);
    }
    while nonce == [0; 32] {
        fill_random(entropy_calls, &mut nonce);
    }
    (LocalSessionChallengeId(challenge), nonce)
}

fn fill_random(entropy_calls: Option<&AtomicUsize>, output: &mut [u8]) {
    if let Some(calls) = entropy_calls {
        calls.fetch_add(1, Ordering::SeqCst);
    }
    OsRng.fill_bytes(output);
}
