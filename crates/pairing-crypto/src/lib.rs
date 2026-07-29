use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ── Constants ────────────────────────────────────────────────────────

#[rustfmt::skip]
pub const DOMAIN_SEPARATOR: [u8; 16] = *b"gocode-pair/v1\0\0";
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

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_serialization_is_deterministic() {
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let bytes = canonical_bytes(&challenge);
        assert_eq!(bytes.len(), 100);
        assert_eq!(&bytes[0..16], &DOMAIN_SEPARATOR);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), VERSION);
    }

    #[test]
    fn domain_and_version_rejected_before_signature_check() {
        let mut challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let keypair = generate_keypair();
        let sig = sign_challenge(&challenge, &keypair);
        assert!(verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 1_752_000_001).is_ok());

        challenge.domain = *b"evil-pair/v1\0\0\0\0";
        let bad = sign_challenge(&challenge, &keypair);
        assert!(matches!(
            verify_pairing(&bad, &keypair.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidDomain)
        ));

        challenge.domain = DOMAIN_SEPARATOR;
        challenge.version = 99;
        let bad2 = sign_challenge(&challenge, &keypair);
        assert!(matches!(
            verify_pairing(&bad2, &keypair.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn expiry_uses_test_clock_not_system_time() {
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1000,
            expires_at: 2000,
            capabilities: 0,
        };
        let keypair = generate_keypair();
        let sig = sign_challenge(&challenge, &keypair);

        assert!(verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 1500).is_ok());
        assert!(matches!(
            verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 2500),
            Err(PairingError::Expired { .. })
        ));
        assert!(matches!(
            verify_pairing(&sig, &keypair.verifying_key().to_bytes(), 500),
            Err(PairingError::FutureChallenge(1000))
        ));
    }
}

#[cfg(test)]
mod golden_vectors {
    use super::*;

    const SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38,
    ];

    fn deterministic_challenge() -> PairingChallenge {
        let key = generate_keypair_deterministic(&SEED);
        let device_id = device_id_from_public_key(&key.verifying_key().to_bytes());
        PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id,
            nonce: [0x42; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        }
    }

    #[test]
    fn golden_canonical_hash_matches_typescript() {
        // Simple challenge — cross-language golden vector
        let challenge = PairingChallenge {
            domain: DOMAIN_SEPARATOR,
            version: VERSION,
            device_id: [0xAA; 32],
            nonce: [0xBB; 32],
            issued_at: 1_752_000_000,
            expires_at: 1_752_003_600,
            capabilities: 0,
        };
        let canonical = canonical_bytes(&challenge);
        let hash = hex::encode(Sha256::digest(&canonical));
        assert_eq!(
            hash,
            "c1578ca6e128651894bcbff1c978fa5c95b9e18a50a92075ac7dedc8bfa0859a"
        );
    }

    #[test]
    fn golden_deterministic_signature_verifies() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let canonical = canonical_bytes(&challenge);

        // Golden: canonical bytes SHA-256 (deterministic)
        let hash = hex::encode(Sha256::digest(&canonical));
        let expected = "2b44fefb452b8e59db4c6bc6b3ac48775c270bfbaa9679b2fae51774a16a21e0";
        assert_eq!(
            hash, expected,
            "deterministic golden hash mismatch — if this fails, update both Rust and TypeScript"
        );
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(sig.public_key, key.verifying_key().to_bytes());
        assert!(verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001).is_ok());
    }

    #[test]
    fn golden_expired_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let result = verify_pairing(&sig, &key.verifying_key().to_bytes(), 9_999_999_999);
        assert!(matches!(result, Err(PairingError::Expired { .. })));
    }

    #[test]
    fn golden_wrong_key_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        let wrong_key = [0xFF; 32];
        assert!(matches!(
            verify_pairing(&sig, &wrong_key, 1_752_000_001),
            Err(PairingError::InvalidSignature)
        ));
    }

    #[test]
    fn golden_replay_rejected() {
        let mut checker = InMemoryReplayChecker::new();
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let sig = sign_challenge(&challenge, &key);
        checker.check_and_record(&sig.challenge.nonce).unwrap();
        assert!(matches!(
            checker.check_and_record(&sig.challenge.nonce),
            Err(PairingError::ReplayDetected)
        ));
    }

    #[test]
    fn golden_wrong_domain_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = PairingChallenge {
            domain: *b"evil-pair/v1\x00\x00\x00\x00",
            ..deterministic_challenge()
        };
        let sig = sign_challenge(&challenge, &key);
        assert!(matches!(
            verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidDomain)
        ));
    }

    #[test]
    fn golden_modified_field_rejected() {
        let key = generate_keypair_deterministic(&SEED);
        let challenge = deterministic_challenge();
        let mut sig = sign_challenge(&challenge, &key);
        // Tamper with expires_at after signing
        sig.challenge.expires_at = 1_752_999_999;
        assert!(matches!(
            verify_pairing(&sig, &key.verifying_key().to_bytes(), 1_752_000_001),
            Err(PairingError::InvalidSignature)
        ));
    }
}
