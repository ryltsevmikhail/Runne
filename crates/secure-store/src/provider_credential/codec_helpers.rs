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

fn take<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], SecureStoreError> {
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
