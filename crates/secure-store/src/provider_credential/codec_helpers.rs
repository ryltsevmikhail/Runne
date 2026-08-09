fn encode_identity(encoded: &mut Vec<u8>, identity: &ExecutableIdentityV1) {
    encoded.extend_from_slice(identity.executable_sha256());
    encoded.extend_from_slice(identity.canonical_path_sha256());
    encoded.extend_from_slice(&identity.byte_length().to_be_bytes());
}

fn decode_identity(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<ExecutableIdentityV1, SecureStoreError> {
    let executable_sha256 = take(encoded, offset)?;
    let canonical_path_sha256 = take(encoded, offset)?;
    let byte_length = u64::from_be_bytes(take(encoded, offset)?);
    ExecutableIdentityV1::new(executable_sha256, canonical_path_sha256, byte_length)
        .map_err(|_| SecureStoreError::CorruptProviderCredential)
}

fn take<const N: usize>(encoded: &[u8], offset: &mut usize) -> Result<[u8; N], SecureStoreError> {
    let end = offset
        .checked_add(N)
        .ok_or(SecureStoreError::CorruptProviderCredential)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(SecureStoreError::CorruptProviderCredential)?
        .try_into()
        .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
    *offset = end;
    Ok(value)
}

fn decode_source_slot(
    encoded: &[u8],
    offset: &mut usize,
    state: source_update::ProviderCredentialSourceSlotState,
) -> Result<source_update::ProviderCredentialSourceSlotVersion, SecureStoreError> {
    let generation = u64::from_be_bytes(take(encoded, offset)?);
    let slot_bytes: [u8; 8] = take(encoded, offset)?;
    if slot_bytes[1..] != [0; 7] {
        return Err(SecureStoreError::CorruptProviderCredential);
    }
    let slot = source_update::ProviderCredentialSourceSlot::from_tag(slot_bytes[0])?;
    source_update::ProviderCredentialSourceSlotVersion::new(slot, generation, state)
}
