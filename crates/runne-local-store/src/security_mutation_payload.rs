use crate::{MutationIdentity, SecurityStateError};
use runne_secure_store::SecurityProfileLock;
use zeroize::Zeroizing;

#[cfg(all(test, feature = "test-support"))]
#[path = "security_mutation_payload_tests.rs"]
mod tests;

const ENVELOPE_MAGIC: &[u8; 4] = b"RNV9";
const ENVELOPE_VERSION: u8 = 1;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;

#[derive(Clone, Copy)]
pub enum PayloadKind {
    Command,
    Outcome,
}

pub fn seal(
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    identity: &MutationIdentity,
    kind: PayloadKind,
    plaintext: &[u8],
) -> Result<Vec<u8>, SecurityStateError> {
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err(SecurityStateError::InvalidTransition);
    }
    let aad = aad(profile, database, identity, kind);
    let ciphertext = lock.encrypt_mutation_payload(database, &aad, plaintext)?;
    let mut encoded = Vec::with_capacity(5 + ciphertext.len());
    encoded.extend_from_slice(ENVELOPE_MAGIC);
    encoded.push(ENVELOPE_VERSION);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

pub fn open(
    lock: &SecurityProfileLock<'_>,
    profile: [u8; 32],
    database: [u8; 32],
    identity: &MutationIdentity,
    kind: PayloadKind,
    stored: &[u8],
    expected_ref: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, SecurityStateError> {
    if stored.len() > MAX_PAYLOAD_BYTES + 64 {
        return Err(SecurityStateError::IdentityConflict);
    }
    let plaintext = if stored.starts_with(ENVELOPE_MAGIC) {
        if stored.get(4) != Some(&ENVELOPE_VERSION) || stored.len() <= 5 {
            return Err(SecurityStateError::IdentityConflict);
        }
        let aad = aad(profile, database, identity, kind);
        lock.decrypt_mutation_payload(database, &aad, &stored[5..])?
    } else {
        Zeroizing::new(stored.to_vec())
    };
    let reference_matches = match kind {
        PayloadKind::Command => {
            crate::security_ledger_v7::digest::command(&plaintext).as_bytes() == expected_ref
        }
        PayloadKind::Outcome => {
            crate::security_ledger_v7::digest::outcome(&plaintext).as_bytes() == expected_ref
        }
    };
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES || !reference_matches {
        return Err(SecurityStateError::IdentityConflict);
    }
    Ok(plaintext)
}

fn aad(
    profile: [u8; 32],
    database: [u8; 32],
    identity: &MutationIdentity,
    kind: PayloadKind,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(256);
    value.extend_from_slice(b"runne/local-store/mutation-payload/aad/v1\0");
    value.extend_from_slice(&profile);
    value.extend_from_slice(&database);
    value.push(match kind {
        PayloadKind::Command => 1,
        PayloadKind::Outcome => 2,
    });
    value.extend_from_slice(&identity.runtime());
    value.extend_from_slice(&identity.principal());
    field(&mut value, identity.operation_name().as_bytes());
    field(&mut value, identity.target_name().as_bytes());
    field(&mut value, identity.target());
    field(&mut value, identity.idempotency_key().as_bytes());
    value.extend_from_slice(&identity.expected_version().to_be_bytes());
    value.extend_from_slice(&identity.semantic_digest());
    value
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
