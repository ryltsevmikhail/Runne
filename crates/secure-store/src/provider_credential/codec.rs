pub struct StoredProviderCredential {
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
    material: ProviderCredentialMaterial,
}

/// Non-secret item metadata used for pre-readiness presence and ACL checks.
pub struct ProviderCredentialMetadata {
    enrollment_state: ProviderCredentialEnrollmentState,
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
}

impl ProviderCredentialMetadata {
    pub fn from_access(access: &ProviderCredentialAccessPolicy, acl_set_digest: [u8; 32]) -> Self {
        Self { enrollment_state: ProviderCredentialEnrollmentState::Complete, writer_identity: access.writer_identity().clone(), reader_identity: access.reader_identity().clone(), acl_set_digest }
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() != PROVIDER_CREDENTIAL_METADATA_BYTES { return Err(SecureStoreError::CorruptProviderCredential); }
        let magic = &encoded[..PROVIDER_CREDENTIAL_METADATA_MAGIC.len()];
        let enrollment_state = if magic == PROVIDER_CREDENTIAL_METADATA_MAGIC { ProviderCredentialEnrollmentState::Complete } else if magic == PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC { ProviderCredentialEnrollmentState::Incomplete } else { return Err(SecureStoreError::CorruptProviderCredential); };
        let mut offset = PROVIDER_CREDENTIAL_METADATA_MAGIC.len();
        let writer_identity = decode_identity(encoded, &mut offset)?;
        let reader_identity = decode_identity(encoded, &mut offset)?;
        let acl_set_digest = take(encoded, &mut offset)?;
        if acl_set_digest == [0; 32] { return Err(SecureStoreError::CorruptProviderCredential); }
        Ok(Self { enrollment_state, writer_identity, reader_identity, acl_set_digest })
    }
    pub fn encode(&self) -> Vec<u8> { self.encode_with_state(ProviderCredentialEnrollmentState::Complete) }
    pub fn encode_incomplete(&self) -> Vec<u8> { self.encode_with_state(ProviderCredentialEnrollmentState::Incomplete) }
    fn encode_with_state(&self, state: ProviderCredentialEnrollmentState) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(PROVIDER_CREDENTIAL_METADATA_BYTES);
        encoded.extend_from_slice(match state { ProviderCredentialEnrollmentState::Incomplete => PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC, ProviderCredentialEnrollmentState::Complete => PROVIDER_CREDENTIAL_METADATA_MAGIC });
        encode_identity(&mut encoded, &self.writer_identity);
        encode_identity(&mut encoded, &self.reader_identity);
        encoded.extend_from_slice(&self.acl_set_digest);
        encoded
    }
    pub fn is_complete(&self) -> bool { self.enrollment_state == ProviderCredentialEnrollmentState::Complete }
    pub fn validate_writer_current(&self) -> Result<(), SecureStoreError> { validate_current_identity(&self.writer_identity).map_err(|_| SecureStoreError::CredentialAccessDenied) }
    pub const fn acl_set_digest(&self) -> [u8; 32] { self.acl_set_digest }
    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool { self.writer_identity == *access.writer_identity() && self.reader_identity == *access.reader_identity() }
}

impl StoredProviderCredential {
    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() < PROVIDER_CREDENTIAL_HEADER_BYTES || &encoded[..PROVIDER_CREDENTIAL_MAGIC.len()] != PROVIDER_CREDENTIAL_MAGIC { return Err(SecureStoreError::CorruptProviderCredential); }
        let mut offset = PROVIDER_CREDENTIAL_MAGIC.len();
        let writer_identity = decode_identity(encoded, &mut offset)?;
        let reader_identity = decode_identity(encoded, &mut offset)?;
        let acl_set_digest = take(encoded, &mut offset)?;
        if acl_set_digest == [0; 32] { return Err(SecureStoreError::CorruptProviderCredential); }
        let credential_length = usize::try_from(u32::from_be_bytes(take(encoded, &mut offset)?)).map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        let expected_length = offset.checked_add(credential_length).ok_or(SecureStoreError::CorruptProviderCredential)?;
        if credential_length == 0 || credential_length > MAX_PROVIDER_CREDENTIAL_BYTES || encoded.len() != expected_length { return Err(SecureStoreError::CorruptProviderCredential); }
        let material = ProviderCredentialMaterial::new(encoded[offset..].to_vec()).map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        Ok(Self { writer_identity, reader_identity, acl_set_digest, material })
    }
    pub fn encode(material: &ProviderCredentialMaterial, access: &ProviderCredentialAccessPolicy, acl_set_digest: [u8; 32]) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        if acl_set_digest == [0; 32] { return Err(SecureStoreError::CredentialAccessDenied); }
        let credential_length = material.with_bytes(<[u8]>::len);
        let encoded_length = PROVIDER_CREDENTIAL_HEADER_BYTES.checked_add(credential_length).ok_or(SecureStoreError::InvalidProviderCredential)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded.try_reserve_exact(encoded_length).map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        encoded.extend_from_slice(PROVIDER_CREDENTIAL_MAGIC);
        encode_identity(&mut encoded, access.writer_identity());
        encode_identity(&mut encoded, access.reader_identity());
        encoded.extend_from_slice(&acl_set_digest);
        encoded.extend_from_slice(&u32::try_from(credential_length).map_err(|_| SecureStoreError::InvalidProviderCredential)?.to_be_bytes());
        material.with_bytes(|bytes| encoded.extend_from_slice(bytes));
        Ok(encoded)
    }
    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool { self.writer_identity == *access.writer_identity() && self.reader_identity == *access.reader_identity() }
    pub fn metadata_matches(&self, metadata: &ProviderCredentialMetadata) -> bool { self.writer_identity == metadata.writer_identity && self.reader_identity == metadata.reader_identity && self.acl_set_digest == metadata.acl_set_digest }
    #[cfg(test)] pub fn validate_reader_current(&self) -> Result<(), SecureStoreError> { validate_current_identity(&self.reader_identity).map_err(|_| SecureStoreError::CredentialAccessDenied) }
    pub const fn acl_set_digest(&self) -> [u8; 32] { self.acl_set_digest }
    pub fn into_material(self) -> ProviderCredentialMaterial { self.material }
}

fn encode_identity(encoded: &mut Vec<u8>, identity: &ExecutableIdentityV1) {
    encoded.extend_from_slice(identity.executable_sha256());
    encoded.extend_from_slice(identity.canonical_path_sha256());
    encoded.extend_from_slice(&identity.byte_length().to_be_bytes());
}
fn decode_identity(encoded: &[u8], offset: &mut usize) -> Result<ExecutableIdentityV1, SecureStoreError> {
    let executable_sha256 = take(encoded, offset)?;
    let canonical_path_sha256 = take(encoded, offset)?;
    let byte_length = u64::from_be_bytes(take(encoded, offset)?);
    ExecutableIdentityV1::new(executable_sha256, canonical_path_sha256, byte_length).map_err(|_| SecureStoreError::CorruptProviderCredential)
}
fn take<const N: usize>(encoded: &[u8], offset: &mut usize) -> Result<[u8; N], SecureStoreError> {
    let end = offset.checked_add(N).ok_or(SecureStoreError::CorruptProviderCredential)?;
    let value = encoded.get(*offset..end).ok_or(SecureStoreError::CorruptProviderCredential)?.try_into().map_err(|_| SecureStoreError::CorruptProviderCredential)?;
    *offset = end;
    Ok(value)
}
