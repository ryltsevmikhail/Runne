const ENROLLMENT_CONTROL_MAGIC: &[u8; 8] = b"GCPCECTL";
const ENROLLMENT_CONTROL_DOMAIN: &[u8] = b"gocode/protected-credential-enrollment-control/v1";
const ENROLLMENT_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"gocode/protected-credential-enrollment-request/v1\0";
const ENROLLMENT_NATIVE_INTENT_DOMAIN: &[u8] =
    b"gocode/protected-credential-enrollment-native-intent/v1\0";
const ENROLLMENT_BROKER_EVIDENCE_DOMAIN: &[u8] =
    b"gocode/protected-credential-enrollment-broker-evidence/v1\0";
const REQUEST_PHASE: u8 = 1;
const ADMISSION_PHASE: u8 = 2;
const REQUEST_BYTES: usize = 8 + 1 + (4 * 16) + (5 * 8) + (7 * 32);
const ADMISSION_BYTES: usize = 8 + 1 + (8 * 32) + (4 * 8) + 16;

include!("credential_enrollment_control/auth.rs");
include!("credential_enrollment_control/types.rs");
include!("credential_enrollment_control/wire.rs");

/// Derives the opaque native-intent lookup key for protected control and HTTP.
#[must_use]
pub fn protected_credential_native_intent_digest(native_intent_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ENROLLMENT_NATIVE_INTENT_DOMAIN);
    digest.update(u64::try_from(native_intent_id.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(native_intent_id.as_bytes());
    digest.finalize().into()
}

/// Commits a protected request to the daemon-owned rendezvous and release.
#[must_use]
pub fn protected_credential_broker_evidence_binding(
    release_tuple: [u8; 32],
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ENROLLMENT_BROKER_EVIDENCE_DOMAIN);
    digest.update(release_tuple);
    digest.update(channel_binding);
    digest.update(publication_public_key);
    digest.finalize().into()
}

#[cfg(test)]
#[path = "credential_enrollment_control_tests.rs"]
mod credential_enrollment_control_tests;
