use crate::{SealedTransactionTag, SecureStoreError, SecurityAnchorV1, StoredSecurityAnchor};

const MAGIC: &[u8; 8] = b"RNTST001";
const MAX_SEAL: usize = 80;

pub(super) fn encode(value: &SecurityAnchorV1) -> Vec<u8> {
    let seal = value.sealed_transaction.as_bytes();
    let mut bytes = Vec::with_capacity(148 + seal.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&value.profile_identity_digest);
    bytes.extend_from_slice(&value.database_identity);
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(&value.transaction_digest);
    bytes.extend_from_slice(&value.previous_anchor_digest);
    bytes.extend_from_slice(&u16::try_from(seal.len()).unwrap_or_default().to_be_bytes());
    bytes.extend_from_slice(seal);
    bytes
}

pub(super) fn decode(bytes: &[u8]) -> Result<StoredSecurityAnchor, SecureStoreError> {
    if bytes.len() < 146 || bytes.get(..8) != Some(MAGIC) {
        return Err(SecureStoreError::CorruptAnchor);
    }
    let mut offset = 8;
    let profile = take::<32>(bytes, &mut offset)?;
    let database = take::<32>(bytes, &mut offset)?;
    let generation = u64::from_be_bytes(take::<8>(bytes, &mut offset)?);
    let transaction = take::<32>(bytes, &mut offset)?;
    let previous = take::<32>(bytes, &mut offset)?;
    let seal_length = usize::from(u16::from_be_bytes(take::<2>(bytes, &mut offset)?));
    if seal_length == 0 || seal_length > MAX_SEAL || bytes.len() != offset + seal_length {
        return Err(SecureStoreError::CorruptAnchor);
    }
    let seal = SealedTransactionTag::from_storage(bytes[offset..].to_vec())?;
    let anchor = SecurityAnchorV1::new(profile, database, generation, transaction, previous, seal)?;
    Ok(StoredSecurityAnchor::V1(anchor))
}

fn take<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], SecureStoreError> {
    let end = offset
        .checked_add(N)
        .ok_or(SecureStoreError::CorruptAnchor)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(SecureStoreError::CorruptAnchor)?;
    let mut output = [0; N];
    output.copy_from_slice(value);
    *offset = end;
    Ok(output)
}

pub(super) fn valid_next(expected: Option<&SecurityAnchorV1>, next: &SecurityAnchorV1) -> bool {
    expected.map_or_else(
        || next.generation == 1 && next.previous_anchor_digest == [0; 32],
        |prior| {
            next.profile_identity_digest == prior.profile_identity_digest
                && next.database_identity == prior.database_identity
                && prior.generation.checked_add(1) == Some(next.generation)
                && next.previous_anchor_digest == prior.digest()
        },
    )
}
