use std::sync::{Mutex, atomic::AtomicUsize};

use hmac::{Hmac, Mac};
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::local_session::{
    BOOTSTRAP_KEY_VERSION_V3, BOOTSTRAP_PROTOCOL_V3, BootstrapProof, BootstrapReservationError,
    BootstrapReservationState, BootstrapReservationStore, ConsumeReservation, ConsumedReservation,
    LocalSessionChallengeId, PreallocateReservation, Reservation,
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use runne_pairing_crypto::{
    BootstrapTranscriptV3, encode_final_transcript, encode_preallocation_transcript,
};
use sha2::Sha256;
use std::sync::atomic::Ordering;

pub const SECRET: [u8; 32] = [7; 32];
pub const EXECUTABLE_SHA256: [u8; 32] = [0x0e; 32];
pub const LAUNCH_AUTHORITY_ID: [u8; 16] =
    [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
pub const CLIENT_NONCE: [u8; 32] = [9; 32];
pub const NOT_BEFORE: &str = "2025-01-01T00:00:00.000000Z";
pub const EXPIRY: &str = "2025-01-01T00:00:30.000000Z";
pub const NOT_BEFORE_MICROS: i64 = 1_735_689_600_000_000;
pub const EXPIRY_MICROS: i64 = 1_735_689_630_000_000;
pub const NOW_MICROS: i64 = 1_735_689_610_000_000;

#[derive(Default)]
pub struct RecordingStore {
    pub calls: AtomicUsize,
    pub allocations: AtomicUsize,
    state: Mutex<Option<Reservation>>,
    observed: Mutex<i64>,
}

impl BootstrapReservationStore for RecordingStore {
    fn preallocate(
        &self,
        input: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.as_ref() {
            return (existing.reservation_key == input.reservation_key)
                .then(|| existing.clone())
                .ok_or(BootstrapReservationError::Capacity);
        }
        self.allocations.fetch_add(1, Ordering::SeqCst);
        let reservation = Reservation {
            reservation_key: input.reservation_key,
            challenge_id: LocalSessionChallengeId([1; 16]),
            server_nonce: [8; 32],
            binding_proof: input.binding_proof,
            key_version: input.key_version,
            client_nonce: input.client_nonce,
            not_before_rfc3339_utc_microseconds: input.not_before_rfc3339_utc_microseconds,
            expiry_rfc3339_utc_microseconds: input.expiry_rfc3339_utc_microseconds,
            not_before_unix_microseconds: input.not_before_unix_microseconds,
            expiry_unix_microseconds: input.expiry_unix_microseconds,
            attempt_count: 0,
            fence: input.fence,
            state: BootstrapReservationState::Reserved,
        };
        *state = Some(reservation.clone());
        Ok(reservation)
    }

    fn consume_final(
        &self,
        input: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        let reservation = state.as_mut().ok_or(BootstrapReservationError::Rejected)?;
        if reservation.challenge_id != input.challenge_id
            || reservation.binding_proof != input.binding_proof
            || reservation.state != BootstrapReservationState::Reserved
            || !(input.verify)(reservation)
        {
            reservation.attempt_count = reservation.attempt_count.saturating_add(1);
            return Err(BootstrapReservationError::Rejected);
        }
        reservation.state = BootstrapReservationState::Consumed;
        Ok(ConsumedReservation {
            reservation_key: reservation.reservation_key,
            challenge_id: reservation.challenge_id,
            consumed_at_unix_microseconds: input.observed_at_unix_microseconds,
            fence: reservation.fence,
        })
    }

    fn observe_clock(&self, now: i64) -> Result<i64, BootstrapReservationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut observed = self.observed.lock().unwrap();
        if now < *observed {
            return Err(BootstrapReservationError::ClockRegression);
        }
        *observed = now;
        Ok(now)
    }
}

pub fn proof_for(
    binding: &RuntimeSessionBinding,
    endpoint: &[u8],
    method: &[u8],
    server_nonce: Option<[u8; 32]>,
) -> BootstrapProof {
    let stable = binding.stable();
    let generation = binding.ephemeral().launch_generation().to_be_bytes();
    let instance = binding.ephemeral().daemon_instance_id().into_bytes();
    let fields: [&[u8]; 16] = [
        BOOTSTRAP_PROTOCOL_V3,
        &LAUNCH_AUTHORITY_ID,
        stable.principal_id().as_str().as_bytes(),
        stable.lineage_id().as_bytes(),
        stable.profile_id().as_bytes(),
        stable.schema_hash(),
        &EXECUTABLE_SHA256,
        &instance,
        &generation,
        binding.ephemeral().session_id(),
        endpoint,
        method,
        NOT_BEFORE.as_bytes(),
        EXPIRY.as_bytes(),
        &CLIENT_NONCE,
        &[],
    ];
    let transcript = BootstrapTranscriptV3 {
        key_version: BOOTSTRAP_KEY_VERSION_V3,
        fields,
    };
    let bytes = match server_nonce {
        Some(nonce) => encode_final_transcript(&transcript, nonce).unwrap(),
        None => encode_preallocation_transcript(&transcript).unwrap(),
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&SECRET).unwrap();
    mac.update(&bytes);
    BootstrapProof::new(mac.finalize().into_bytes().into())
}

pub fn binding(generation: u64) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "runne-ui-client/1",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([
            1,
            143,
            46,
            58,
            112,
            0,
            112,
            0,
            128,
            0,
            0,
            0,
            0,
            0,
            0,
            generation as u8,
        ]),
        generation,
        [5; 16],
        3,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}
