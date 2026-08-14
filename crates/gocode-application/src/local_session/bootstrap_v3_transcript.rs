use chrono::{DateTime, Utc};
use gocode_pairing_crypto::{
    BootstrapTranscriptV3, encode_final_transcript, encode_preallocation_transcript,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{
    BOOTSTRAP_FINAL_ENDPOINT_V3, BOOTSTRAP_HTTP_METHOD_V3, BOOTSTRAP_PROTOCOL_V3, BootstrapProof,
    BootstrapReservationError, LocalSessionError, Reservation,
};

pub(super) fn final_proof_matches(
    binding: &gocode_api::RuntimeSessionBinding,
    launch_authority_id: &[u8; 16],
    executable_sha256: &[u8; 32],
    secret: &[u8; 32],
    proof: &BootstrapProof,
    reservation: &Reservation,
) -> bool {
    if canonical_timestamp(&reservation.not_before_rfc3339_utc_microseconds).ok()
        != Some(reservation.not_before_unix_microseconds)
        || canonical_timestamp(&reservation.expiry_rfc3339_utc_microseconds).ok()
            != Some(reservation.expiry_unix_microseconds)
    {
        return false;
    }
    encode_stage(
        binding,
        launch_authority_id,
        executable_sha256,
        reservation.key_version,
        BOOTSTRAP_FINAL_ENDPOINT_V3,
        &reservation.not_before_rfc3339_utc_microseconds,
        &reservation.expiry_rfc3339_utc_microseconds,
        &reservation.client_nonce,
        Some(reservation.server_nonce),
    )
    .is_ok_and(|transcript| hmac_matches(secret, &transcript, proof))
}

pub(super) fn canonical_timestamp(value: &str) -> Result<i64, LocalSessionError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| LocalSessionError::Unauthorized)?
        .with_timezone(&Utc);
    if parsed.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string() != value {
        return Err(LocalSessionError::Unauthorized);
    }
    Ok(parsed.timestamp_micros())
}

pub(super) fn hmac_matches(secret: &[u8; 32], transcript: &[u8], proof: &BootstrapProof) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(transcript);
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    bool::from(expected.ct_eq(proof.as_bytes()))
}

pub(super) fn binding_proof(
    binding: &gocode_api::RuntimeSessionBinding,
    launch_authority_id: &[u8; 16],
    executable_sha256: &[u8; 32],
    key_version: u16,
) -> Result<[u8; 32], LocalSessionError> {
    let bytes = encode_stage(
        binding,
        launch_authority_id,
        executable_sha256,
        key_version,
        b"",
        "",
        "",
        &[],
        None,
    )?;
    Ok(Sha256::digest(bytes).into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_stage(
    binding: &gocode_api::RuntimeSessionBinding,
    launch_authority_id: &[u8; 16],
    executable_sha256: &[u8; 32],
    key_version: u16,
    endpoint: &[u8],
    not_before: &str,
    expiry: &str,
    client_nonce: &[u8],
    server_nonce: Option<[u8; 32]>,
) -> Result<Vec<u8>, LocalSessionError> {
    let stable = binding.stable();
    let generation = binding.ephemeral().launch_generation().to_be_bytes();
    let instance = binding.ephemeral().daemon_instance_id().into_bytes();
    let fields: [&[u8]; 16] = [
        BOOTSTRAP_PROTOCOL_V3,
        launch_authority_id,
        stable.principal_id().as_str().as_bytes(),
        stable.lineage_id().as_bytes(),
        stable.profile_id().as_bytes(),
        stable.schema_hash(),
        executable_sha256,
        &instance,
        &generation,
        binding.ephemeral().session_id(),
        endpoint,
        BOOTSTRAP_HTTP_METHOD_V3,
        not_before.as_bytes(),
        expiry.as_bytes(),
        client_nonce,
        &[],
    ];
    let transcript = BootstrapTranscriptV3 {
        key_version,
        fields,
    };
    match server_nonce {
        Some(nonce) => encode_final_transcript(&transcript, nonce),
        None => encode_preallocation_transcript(&transcript),
    }
    .map_err(|_| LocalSessionError::Unauthorized)
}

pub(super) const fn map_store_error(error: BootstrapReservationError) -> LocalSessionError {
    match error {
        BootstrapReservationError::Capacity | BootstrapReservationError::Storage => {
            LocalSessionError::Unavailable
        }
        BootstrapReservationError::Rejected | BootstrapReservationError::ClockRegression => {
            LocalSessionError::Unauthorized
        }
    }
}
