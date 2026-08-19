use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod bootstrap_v3;

pub use bootstrap_v3::{
    BOOTSTRAP_TRANSCRIPT_DOMAIN, BOOTSTRAP_TRANSCRIPT_FIELD_COUNT, BootstrapTranscriptError,
    BootstrapTranscriptV3, SERVER_NONCE_FIELD_INDEX, encode_final_transcript,
    encode_preallocation_transcript,
};

// ── Constants ────────────────────────────────────────────────────────

#[rustfmt::skip]
pub const DOMAIN_SEPARATOR: [u8; 16] = *b"runne-pair/v1\0\0\0";
pub const VERSION: u16 = 1;

// ── Types ────────────────────────────────────────────────────────────

/// Canonical challenge payload — field order is normative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingChallenge {
    pub domain: [u8; 16],    // DOMAIN_SEPARATOR
    pub version: u16,        // big-endian
    pub device_id: [u8; 32], // SHA-256 of device public key
    pub nonce: [u8; 32],     // random
    pub issued_at: u64,      // Unix seconds, big-endian
    pub expires_at: u64,     // Unix seconds, big-endian
    pub capabilities: u16,   // reserved, big-endian
}

/// Canonical signed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingSignature {
    pub challenge: PairingChallenge,
    pub public_key: [u8; 32], // Ed25519 public key
    pub signature: [u8; 64],  // Ed25519 signature over canonical bytes
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("invalid domain separator")]
    InvalidDomain,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("challenge expired at {expired_at} (now: {now})")]
    Expired { expired_at: u64, now: u64 },
    #[error("challenge issued in the future: {0}")]
    FutureChallenge(u64),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("replay detected: nonce already used")]
    ReplayDetected,
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ── Canonical serialization ──────────────────────────────────────────

/// Canonical big-endian byte serialization.
/// Field order: `domain`(16) + version(2 BE) + `device_id`(32) + `nonce`(32)
/// + `issued_at`(8 BE) + `expires_at`(8 BE) + `capabilities`(2 BE) = 100 bytes.
#[must_use]
pub fn canonical_bytes(challenge: &PairingChallenge) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);
    buf.extend_from_slice(&challenge.domain);
    buf.extend_from_slice(&challenge.version.to_be_bytes());
    buf.extend_from_slice(&challenge.device_id);
    buf.extend_from_slice(&challenge.nonce);
    buf.extend_from_slice(&challenge.issued_at.to_be_bytes());
    buf.extend_from_slice(&challenge.expires_at.to_be_bytes());
    buf.extend_from_slice(&challenge.capabilities.to_be_bytes());
    buf
}

// ── Key generation ───────────────────────────────────────────────────

/// Deterministic Ed25519 keypair from 32-byte seed.
#[must_use]
pub fn generate_keypair_deterministic(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Random keypair — test use only.
#[must_use]
pub fn generate_keypair() -> SigningKey {
    use rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

// ── Sign / Verify ────────────────────────────────────────────────────

/// Sign a challenge — canonical bytes, then Ed25519.
///
/// # Errors
///
/// Never fails (signing is infallible for valid keys).
#[must_use]
pub fn sign_challenge(challenge: &PairingChallenge, key: &SigningKey) -> PairingSignature {
    let message = canonical_bytes(challenge);
    let sig = key.sign(&message);
    PairingSignature {
        challenge: challenge.clone(),
        public_key: key.verifying_key().to_bytes(),
        signature: sig.to_bytes(),
    }
}

/// Verify a pairing signature with test clock `now_secs`.
///
/// # Errors
///
/// Returns `PairingError` for domain mismatch, version mismatch, expiry, or invalid signature.
///
/// Checks: domain, version, key match, expiry (test clock), Ed25519.
pub fn verify_pairing(
    signed: &PairingSignature,
    expected_public_key: &[u8; 32],
    now_secs: u64,
) -> Result<(), PairingError> {
    if signed.challenge.domain != DOMAIN_SEPARATOR {
        return Err(PairingError::InvalidDomain);
    }
    if signed.challenge.version != VERSION {
        return Err(PairingError::UnsupportedVersion(signed.challenge.version));
    }
    if signed.public_key != *expected_public_key {
        return Err(PairingError::InvalidSignature);
    }
    if now_secs > signed.challenge.expires_at {
        return Err(PairingError::Expired {
            expired_at: signed.challenge.expires_at,
            now: now_secs,
        });
    }
    if now_secs < signed.challenge.issued_at {
        return Err(PairingError::FutureChallenge(signed.challenge.issued_at));
    }

    let vk = VerifyingKey::from_bytes(expected_public_key)
        .map_err(|_| PairingError::InvalidSignature)?;
    let message = canonical_bytes(&signed.challenge);
    vk.verify(
        &message,
        &ed25519_dalek::Signature::from_bytes(&signed.signature),
    )
    .map_err(|_| PairingError::InvalidSignature)
}

/// Compute `device_id` as SHA-256 of the device public key.
#[must_use]
pub fn device_id_from_public_key(pk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pk);
    hasher.finalize().into()
}

// ── Replay protection ────────────────────────────────────────────────

/// Replay protection interface — in-memory test double.
pub trait ReplayChecker {
    /// Check a nonce for replay, recording it if unseen.
    ///
    /// # Errors
    ///
    /// Returns `ReplayDetected` if the nonce was already seen.
    fn check_and_record(&mut self, nonce: &[u8; 32]) -> Result<(), PairingError>;
}

#[derive(Default)]
pub struct InMemoryReplayChecker {
    seen: std::collections::HashSet<[u8; 32]>,
}

impl InMemoryReplayChecker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashSet::new(),
        }
    }
}

impl ReplayChecker for InMemoryReplayChecker {
    fn check_and_record(&mut self, nonce: &[u8; 32]) -> Result<(), PairingError> {
        if !self.seen.insert(*nonce) {
            return Err(PairingError::ReplayDetected);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    include!("tests/basic.rs");
}

#[cfg(test)]
mod golden_vectors {
    include!("tests/golden_vectors.rs");
}
