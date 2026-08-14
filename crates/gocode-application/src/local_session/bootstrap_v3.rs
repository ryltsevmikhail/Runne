use std::{
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    time::Duration,
};

use sha2::{Digest, Sha256};

use super::{
    AuthenticatedRuntimeSession, BootstrapProof, ConsumeReservation, LocalSessionChallenge,
    LocalSessionChallengeId, LocalSessionError, LocalSessionService, PreallocateReservation,
    Reservation, RuntimeSessionAuthority, Session,
    bootstrap_v3_transcript::{
        binding_proof, canonical_timestamp, encode_stage, final_proof_matches, hmac_matches,
        map_store_error,
    },
};

/// Exact wire version for the durable bootstrap protocol.
pub const BOOTSTRAP_WIRE_VERSION_V3: &str = "3";
/// Sole supported HMAC key/transcript version.
pub const BOOTSTRAP_KEY_VERSION_V3: u16 = 1;
/// Canonical protocol field encoded into both proof stages.
pub const BOOTSTRAP_PROTOCOL_V3: &[u8] = b"gocode-local-session-v3";
/// Authenticated preallocation endpoint field.
pub const BOOTSTRAP_PREALLOCATION_ENDPOINT_V3: &[u8] = b"/v1/local-session/challenges";
/// Authenticated final-proof endpoint field.
pub const BOOTSTRAP_FINAL_ENDPOINT_V3: &[u8] = b"/v1/local-session/authenticate";
/// Authenticated HTTP method field.
pub const BOOTSTRAP_HTTP_METHOD_V3: &[u8] = b"POST";
const MAX_BOOTSTRAP_WINDOW_MICROSECONDS: i64 = 30_000_000;

/// One observation of wall time and daemon-launch monotonic time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapClock {
    pub observed_at_unix_microseconds: i64,
    pub session_monotonic: Duration,
}

impl BootstrapClock {
    pub const fn new(observed_at_unix_microseconds: i64, session_monotonic: Duration) -> Self {
        Self {
            observed_at_unix_microseconds,
            session_monotonic,
        }
    }
}

/// Client-authenticated preallocation proof inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct BootstrapPreallocationProof {
    pub key_version: u16,
    pub client_nonce: [u8; 32],
    pub not_before_rfc3339_utc_microseconds: String,
    pub expiry_rfc3339_utc_microseconds: String,
    pub proof: BootstrapProof,
}

impl LocalSessionService {
    /// Verifies stateless preauthentication before durable allocation.
    pub fn preallocate(
        &mut self,
        proof: BootstrapPreallocationProof,
        now: BootstrapClock,
    ) -> Result<LocalSessionChallenge, LocalSessionError> {
        if proof.key_version != BOOTSTRAP_KEY_VERSION_V3
            || self.launch_authority_id == [0; 16]
            || self.executable_sha256 == [0; 32]
        {
            return Err(LocalSessionError::Unauthorized);
        }
        self.enforce_bootstrap_deadline(now.session_monotonic)?;
        let secret = self
            .bootstrap_secret
            .as_ref()
            .ok_or(LocalSessionError::Unauthorized)?;
        let not_before = canonical_timestamp(&proof.not_before_rfc3339_utc_microseconds)?;
        let expiry = canonical_timestamp(&proof.expiry_rfc3339_utc_microseconds)?;
        if proof.client_nonce == [0; 32]
            || now.observed_at_unix_microseconds < 0
            || not_before > now.observed_at_unix_microseconds
            || now.observed_at_unix_microseconds >= expiry
            || expiry
                .checked_sub(not_before)
                .is_none_or(|window| window <= 0 || window > MAX_BOOTSTRAP_WINDOW_MICROSECONDS)
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let transcript = encode_stage(
            &self.binding,
            &self.launch_authority_id,
            &self.executable_sha256,
            proof.key_version,
            BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
            &proof.not_before_rfc3339_utc_microseconds,
            &proof.expiry_rfc3339_utc_microseconds,
            &proof.client_nonce,
            None,
        )?;
        if !hmac_matches(secret, &transcript, &proof.proof) {
            return Err(LocalSessionError::Unauthorized);
        }
        let reservation = self
            .reservation_store
            .preallocate(PreallocateReservation {
                reservation_key: Sha256::digest(&transcript).into(),
                binding_proof: binding_proof(
                    &self.binding,
                    &self.launch_authority_id,
                    &self.executable_sha256,
                    proof.key_version,
                )?,
                key_version: proof.key_version,
                client_nonce: proof.client_nonce,
                not_before_rfc3339_utc_microseconds: proof.not_before_rfc3339_utc_microseconds,
                expiry_rfc3339_utc_microseconds: proof.expiry_rfc3339_utc_microseconds,
                not_before_unix_microseconds: not_before,
                expiry_unix_microseconds: expiry,
                observed_at_unix_microseconds: now.observed_at_unix_microseconds,
                fence: self.binding.ephemeral().launch_generation(),
            })
            .map_err(map_store_error)?;
        Ok(LocalSessionChallenge {
            id: reservation.challenge_id,
            server_nonce: reservation.server_nonce,
        })
    }

    /// Atomically verifies and consumes one durable final-proof reservation.
    pub fn consume_final(
        &mut self,
        challenge_id: LocalSessionChallengeId,
        proof: BootstrapProof,
        authority_bytes: [u8; 32],
        now: BootstrapClock,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.prune(now.session_monotonic);
        self.enforce_bootstrap_deadline(now.session_monotonic)?;
        let principal = self.binding.stable().principal_id().as_str();
        let principal_sessions = self
            .sessions
            .values()
            .filter(|session| {
                session
                    .authenticated
                    .binding
                    .stable()
                    .principal_id()
                    .as_str()
                    == principal
            })
            .count();
        if authority_bytes == [0; 32]
            || self.sessions.len() >= super::MAX_SESSIONS
            || principal_sessions >= super::MAX_SESSIONS_PER_PRINCIPAL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        let binding_proof = binding_proof(
            &self.binding,
            &self.launch_authority_id,
            &self.executable_sha256,
            BOOTSTRAP_KEY_VERSION_V3,
        )?;
        let secret = self
            .bootstrap_secret
            .as_ref()
            .ok_or(LocalSessionError::Unauthorized)?;
        let binding = self.binding.clone();
        let launch_authority_id = self.launch_authority_id;
        let executable_sha256 = self.executable_sha256;
        let verify = |reservation: &Reservation| {
            reservation.key_version == BOOTSTRAP_KEY_VERSION_V3
                && reservation.binding_proof == binding_proof
                && final_proof_matches(
                    &binding,
                    &launch_authority_id,
                    &executable_sha256,
                    secret,
                    &proof,
                    reservation,
                )
        };
        self.reservation_store
            .consume_final(ConsumeReservation {
                challenge_id,
                binding_proof,
                authority_digest: Sha256::digest(authority_bytes).into(),
                observed_at_unix_microseconds: now.observed_at_unix_microseconds,
                verify: &verify,
            })
            .map_err(map_store_error)?;
        let authenticated = AuthenticatedRuntimeSession {
            binding: self.binding.clone(),
            expires_at_monotonic: now.session_monotonic + gocode_api::LOCAL_RUNTIME_SESSION_TTL,
        };
        self.sessions.insert(
            authority_bytes,
            Session {
                authenticated: authenticated.clone(),
                authority: RuntimeSessionAuthority(zeroize::Zeroizing::new(authority_bytes)),
                epoch: self.authorization_epoch,
                generation: self.binding.ephemeral().launch_generation(),
                issuer_state: Arc::new(super::ReplayBaselineIssuerState {
                    revoked: AtomicBool::new(false),
                }),
            },
        );
        if self.bootstrap_policy == super::BootstrapPolicy::OneTimeProtected {
            self.bootstrap_secret.take();
            self.bootstrap_expires_at = None;
        }
        Ok(authenticated)
    }
}
