impl StoredProviderCredential {
    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() < PROVIDER_CREDENTIAL_HEADER_BYTES {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let magic = &encoded[..PROVIDER_CREDENTIAL_MAGIC.len()];
        let (has_revision, kind) = if magic == PROVIDER_CREDENTIAL_MAGIC {
            (false, ProviderCredentialMaterialKind::Legacy)
        } else if magic == PROVIDER_CREDENTIAL_V2_MAGIC {
            (true, ProviderCredentialMaterialKind::Legacy)
        } else if magic == PROVIDER_CREDENTIAL_OAUTH_MAGIC {
            (true, ProviderCredentialMaterialKind::NativeOAuth)
        } else {
            return Err(SecureStoreError::CorruptProviderCredential);
        };
        let mut offset = PROVIDER_CREDENTIAL_MAGIC.len();
        let writer_identity = decode_identity(encoded, &mut offset)?;
        let reader_identity = decode_identity(encoded, &mut offset)?;
        let acl_set_digest = take(encoded, &mut offset)?;
        if acl_set_digest == [0; 32] {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let source_revision = has_revision
            .then(|| take(encoded, &mut offset))
            .transpose()?
            .map(ProviderCredentialSourceRevision::new)
            .transpose()
            .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        let credential_length = usize::try_from(u32::from_be_bytes(take(encoded, &mut offset)?))
            .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        let expected_length = offset
            .checked_add(credential_length)
            .ok_or(SecureStoreError::CorruptProviderCredential)?;
        let max_length = match kind {
            ProviderCredentialMaterialKind::Legacy => MAX_PROVIDER_CREDENTIAL_BYTES,
            ProviderCredentialMaterialKind::NativeOAuth => MAX_NATIVE_OAUTH_CREDENTIAL_BYTES,
        };
        if credential_length == 0
            || credential_length > max_length
            || encoded.len() != expected_length
        {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let material = match kind {
            ProviderCredentialMaterialKind::Legacy => {
                ProviderCredentialMaterial::new(encoded[offset..].to_vec())
            }
            ProviderCredentialMaterialKind::NativeOAuth => {
                ProviderCredentialMaterial::new_native_oauth(encoded[offset..].to_vec())
            }
        }
        .map_err(|_| SecureStoreError::CorruptProviderCredential)?;
        Ok(Self {
            writer_identity,
            reader_identity,
            acl_set_digest,
            source_revision,
            material,
        })
    }

    pub fn encode(
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        Self::encode_inner(material, access, acl_set_digest, None)
    }

    pub fn encode_with_revision(
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
        source_revision: ProviderCredentialSourceRevision,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        Self::encode_inner(material, access, acl_set_digest, Some(source_revision))
    }

    fn encode_inner(
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
        source_revision: Option<ProviderCredentialSourceRevision>,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        if acl_set_digest == [0; 32] {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        if material.kind() == ProviderCredentialMaterialKind::NativeOAuth
            && source_revision.is_none()
        {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let credential_length = material.with_bytes(<[u8]>::len);
        let encoded_length = PROVIDER_CREDENTIAL_HEADER_BYTES
            .checked_add(source_revision.map_or(0, |_| PROVIDER_CREDENTIAL_REVISION_BYTES))
            .and_then(|length| length.checked_add(credential_length))
            .ok_or(SecureStoreError::InvalidProviderCredential)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(encoded_length)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        encoded.extend_from_slice(
            if material.kind() == ProviderCredentialMaterialKind::NativeOAuth {
                PROVIDER_CREDENTIAL_OAUTH_MAGIC
            } else if source_revision.is_some() {
                PROVIDER_CREDENTIAL_V2_MAGIC
            } else {
                PROVIDER_CREDENTIAL_MAGIC
            },
        );
        encode_identity(&mut encoded, access.writer_identity());
        encode_identity(&mut encoded, access.reader_identity());
        encoded.extend_from_slice(&acl_set_digest);
        if let Some(revision) = source_revision {
            encoded.extend_from_slice(revision.as_bytes());
        }
        encoded.extend_from_slice(
            &u32::try_from(credential_length)
                .map_err(|_| SecureStoreError::InvalidProviderCredential)?
                .to_be_bytes(),
        );
        material.with_bytes(|bytes| encoded.extend_from_slice(bytes));
        Ok(encoded)
    }

    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool {
        self.writer_identity == *access.writer_identity()
            && self.reader_identity == *access.reader_identity()
    }

    pub fn metadata_matches(&self, metadata: &ProviderCredentialMetadata) -> bool {
        self.writer_identity == metadata.writer_identity
            && self.reader_identity == metadata.reader_identity
            && self.acl_set_digest == metadata.acl_set_digest
            && self.source_revision == metadata.source_revision
    }

    pub fn material_matches(&self, expected: &ProviderCredentialMaterial) -> bool {
        self.material
            .with_bytes(|stored| expected.with_bytes(|expected| stored == expected))
    }

    #[cfg(test)]
    pub fn validate_reader_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.reader_identity)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }

    pub const fn acl_set_digest(&self) -> [u8; 32] {
        self.acl_set_digest
    }

    #[cfg(not(target_os = "macos"))]
    pub const fn source_revision(&self) -> Option<ProviderCredentialSourceRevision> {
        self.source_revision
    }

    pub fn into_material(self) -> ProviderCredentialMaterial {
        self.material
    }

    pub fn into_source(self) -> Result<ProviderCredentialSource, SecureStoreError> {
        let revision = self
            .source_revision
            .ok_or(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)?;
        Ok(ProviderCredentialSource::new(self.material, revision))
    }
}
