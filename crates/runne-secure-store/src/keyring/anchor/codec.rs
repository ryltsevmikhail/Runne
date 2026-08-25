use rand::{RngCore as _, rngs::OsRng};

use crate::{SealedTransactionTag, SecureStoreError, SecurityAnchorV1};

use super::super::SECURITY_ANCHOR_MAGIC;

pub(super) fn profile_key() -> Result<Vec<u8>, SecureStoreError> {
    let mut key = vec![0_u8; 32];
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| SecureStoreError::Unavailable)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(SecureStoreError::Unavailable);
    }
    Ok(key)
}

pub(super) fn seal_input(
    profile: [u8; 32],
    database: [u8; 32],
    generation: u64,
    transaction: [u8; 32],
    previous: [u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + 32 + 32 + 8 + 32 + 32);
    input.extend_from_slice(b"runne-seal-v1\0");
    input.extend_from_slice(&profile);
    input.extend_from_slice(&database);
    input.extend_from_slice(&generation.to_be_bytes());
    input.extend_from_slice(&transaction);
    input.extend_from_slice(&previous);
    input
}

pub(super) fn encode_anchor(anchor: &SecurityAnchorV1) -> Vec<u8> {
    let seal = anchor.sealed_transaction.as_bytes();
    let mut encoded = Vec::with_capacity(145 + seal.len());
    encoded.extend_from_slice(SECURITY_ANCHOR_MAGIC);
    encoded.extend_from_slice(&anchor.profile_identity_digest);
    encoded.extend_from_slice(&anchor.database_identity);
    encoded.extend_from_slice(&anchor.generation.to_be_bytes());
    encoded.extend_from_slice(&anchor.transaction_digest);
    encoded.extend_from_slice(&anchor.previous_anchor_digest);
    encoded.push(u8::try_from(seal.len()).expect("sealed transaction is bounded"));
    encoded.extend_from_slice(seal);
    encoded
}

pub(super) fn decode_anchor(bytes: &[u8]) -> Result<SecurityAnchorV1, SecureStoreError> {
    if bytes.len() < 145 || bytes.get(..8) != Some(SECURITY_ANCHOR_MAGIC) {
        return Err(SecureStoreError::CorruptAnchor);
    }
    let mut offset = 8;
    let take = |offset: &mut usize, length: usize| -> Result<&[u8], SecureStoreError> {
        let end = offset
            .checked_add(length)
            .ok_or(SecureStoreError::CorruptAnchor)?;
        let value = bytes
            .get(*offset..end)
            .ok_or(SecureStoreError::CorruptAnchor)?;
        *offset = end;
        Ok(value)
    };
    let profile = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    let database = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    let generation = u64::from_be_bytes(
        take(&mut offset, 8)?
            .try_into()
            .map_err(|_| SecureStoreError::CorruptAnchor)?,
    );
    let transaction = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    let previous = take(&mut offset, 32)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    let seal_length = usize::from(
        *take(&mut offset, 1)?
            .first()
            .ok_or(SecureStoreError::CorruptAnchor)?,
    );
    if offset.checked_add(seal_length) != Some(bytes.len()) {
        return Err(SecureStoreError::CorruptAnchor);
    }
    let seal = SealedTransactionTag::from_storage(take(&mut offset, seal_length)?.to_vec())
        .map_err(|_| SecureStoreError::CorruptAnchor)?;
    SecurityAnchorV1::new(profile, database, generation, transaction, previous, seal)
        .map_err(|_| SecureStoreError::CorruptAnchor)
}
