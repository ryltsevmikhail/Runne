use super::LocalSessionChallengeId;

/// Maximum number of unexpired reservations and tombstones.
pub const MAX_BOOTSTRAP_RESERVATIONS: usize = 32;
/// Maximum durable final-proof attempts before a reservation is fenced.
pub const MAX_BOOTSTRAP_FINAL_ATTEMPTS: u16 = 8;

/// Durable reservation lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapReservationState {
    Reserved,
    Consumed,
    Fenced,
}

/// Authenticated input from which the store may allocate one reservation.
#[derive(Clone, Eq, PartialEq)]
pub struct PreallocateReservation {
    pub reservation_key: [u8; 32],
    pub binding_proof: [u8; 32],
    pub key_version: u16,
    pub client_nonce: [u8; 32],
    pub not_before_rfc3339_utc_microseconds: String,
    pub expiry_rfc3339_utc_microseconds: String,
    pub not_before_unix_microseconds: i64,
    pub expiry_unix_microseconds: i64,
    pub observed_at_unix_microseconds: i64,
    pub fence: u64,
}

/// Durable challenge material and exact proof inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct Reservation {
    pub reservation_key: [u8; 32],
    pub challenge_id: LocalSessionChallengeId,
    pub server_nonce: [u8; 32],
    pub binding_proof: [u8; 32],
    pub key_version: u16,
    pub client_nonce: [u8; 32],
    pub not_before_rfc3339_utc_microseconds: String,
    pub expiry_rfc3339_utc_microseconds: String,
    pub not_before_unix_microseconds: i64,
    pub expiry_unix_microseconds: i64,
    pub attempt_count: u16,
    pub fence: u64,
    pub state: BootstrapReservationState,
}

/// Atomic compare-and-consume input. Verification remains application-owned.
pub struct ConsumeReservation<'a> {
    pub challenge_id: LocalSessionChallengeId,
    pub binding_proof: [u8; 32],
    pub authority_digest: [u8; 32],
    pub observed_at_unix_microseconds: i64,
    pub verify: &'a (dyn Fn(&Reservation) -> bool + Send + Sync),
}

/// Durable evidence returned after the sole successful consume.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConsumedReservation {
    pub reservation_key: [u8; 32],
    pub challenge_id: LocalSessionChallengeId,
    pub consumed_at_unix_microseconds: i64,
    pub fence: u64,
}

/// Closed reservation persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapReservationError {
    Rejected,
    Capacity,
    ClockRegression,
    Storage,
}

/// Durable bootstrap reservation, tombstone, and clock port.
pub trait BootstrapReservationStore: Send + Sync {
    fn preallocate(
        &self,
        input: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError>;

    fn consume_final(
        &self,
        input: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError>;

    fn observe_clock(&self, now: i64) -> Result<i64, BootstrapReservationError>;
}

pub(crate) struct UnavailableBootstrapReservationStore;

impl BootstrapReservationStore for UnavailableBootstrapReservationStore {
    fn preallocate(
        &self,
        _: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn consume_final(
        &self,
        _: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }

    fn observe_clock(&self, _: i64) -> Result<i64, BootstrapReservationError> {
        Err(BootstrapReservationError::Storage)
    }
}
