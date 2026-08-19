pub struct StoredProviderCredential {
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
    source_revision: Option<ProviderCredentialSourceRevision>,
    material: ProviderCredentialMaterial,
}

/// Non-secret item metadata used for pre-readiness presence and ACL checks.
#[derive(Clone)]
pub struct ProviderCredentialMetadata {
    enrollment_state: ProviderCredentialEnrollmentState,
    writer_identity: ExecutableIdentityV1,
    reader_identity: ExecutableIdentityV1,
    acl_set_digest: [u8; 32],
    source_revision: Option<ProviderCredentialSourceRevision>,
    source_slot: Option<source_update::ProviderCredentialSourceSlotVersion>,
}

impl ProviderCredentialMetadata {
    pub fn from_access(access: &ProviderCredentialAccessPolicy, acl_set_digest: [u8; 32]) -> Self {
        Self::from_access_inner(access, acl_set_digest, None)
    }

    pub fn from_access_revision(
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
        source_revision: ProviderCredentialSourceRevision,
    ) -> Self {
        Self::from_access_inner(access, acl_set_digest, Some(source_revision))
    }

    fn from_access_inner(
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
        source_revision: Option<ProviderCredentialSourceRevision>,
    ) -> Self {
        Self {
            enrollment_state: ProviderCredentialEnrollmentState::Complete,
            writer_identity: access.writer_identity().clone(),
            reader_identity: access.reader_identity().clone(),
            acl_set_digest,
            source_revision,
            source_slot: None,
        }
    }

    pub fn from_source_slot(
        access: &ProviderCredentialAccessPolicy,
        acl_set_digest: [u8; 32],
        source_revision: ProviderCredentialSourceRevision,
        source_slot: source_update::ProviderCredentialSourceSlotVersion,
    ) -> Self {
        Self {
            enrollment_state: ProviderCredentialEnrollmentState::Complete,
            writer_identity: access.writer_identity().clone(),
            reader_identity: access.reader_identity().clone(),
            acl_set_digest,
            source_revision: Some(source_revision),
            source_slot: Some(source_slot),
        }
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SecureStoreError> {
        if encoded.len() != PROVIDER_CREDENTIAL_METADATA_BYTES
            && encoded.len()
                != PROVIDER_CREDENTIAL_METADATA_BYTES + PROVIDER_CREDENTIAL_REVISION_BYTES
            && encoded.len()
                != PROVIDER_CREDENTIAL_METADATA_BYTES
                    + PROVIDER_CREDENTIAL_REVISION_BYTES
                    + PROVIDER_CREDENTIAL_SOURCE_SLOT_BYTES
        {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        let magic = &encoded[..PROVIDER_CREDENTIAL_METADATA_MAGIC.len()];
        let (enrollment_state, has_revision, source_state) = match magic {
            value if value == PROVIDER_CREDENTIAL_METADATA_MAGIC => {
                (ProviderCredentialEnrollmentState::Complete, false, None)
            }
            value if value == PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC => {
                (ProviderCredentialEnrollmentState::Incomplete, false, None)
            }
            value if value == PROVIDER_CREDENTIAL_METADATA_V2_MAGIC => {
                (ProviderCredentialEnrollmentState::Complete, true, None)
            }
            value if value == PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_V2_MAGIC => {
                (ProviderCredentialEnrollmentState::Incomplete, true, None)
            }
            value if value == PROVIDER_CREDENTIAL_SOURCE_INCOMPLETE_MAGIC => (
                ProviderCredentialEnrollmentState::Incomplete,
                true,
                Some(source_update::ProviderCredentialSourceSlotState::Pending),
            ),
            value if value == PROVIDER_CREDENTIAL_SOURCE_PENDING_MAGIC => (
                ProviderCredentialEnrollmentState::Complete,
                true,
                Some(source_update::ProviderCredentialSourceSlotState::Pending),
            ),
            value if value == PROVIDER_CREDENTIAL_SOURCE_COMMITTED_MAGIC => (
                ProviderCredentialEnrollmentState::Complete,
                true,
                Some(source_update::ProviderCredentialSourceSlotState::Committed),
            ),
            _ => return Err(SecureStoreError::CorruptProviderCredential),
        };
        let mut offset = PROVIDER_CREDENTIAL_METADATA_MAGIC.len();
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
        let source_slot = source_state
            .map(|state| decode_source_slot(encoded, &mut offset, state))
            .transpose()?;
        if offset != encoded.len() {
            return Err(SecureStoreError::CorruptProviderCredential);
        }
        Ok(Self {
            enrollment_state,
            writer_identity,
            reader_identity,
            acl_set_digest,
            source_revision,
            source_slot,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_state(ProviderCredentialEnrollmentState::Complete)
    }

    pub fn encode_incomplete(&self) -> Vec<u8> {
        self.encode_with_state(ProviderCredentialEnrollmentState::Incomplete)
    }

    fn encode_with_state(&self, state: ProviderCredentialEnrollmentState) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            PROVIDER_CREDENTIAL_METADATA_BYTES
                + self
                    .source_revision
                    .map_or(0, |_| PROVIDER_CREDENTIAL_REVISION_BYTES)
                + self
                    .source_slot
                    .map_or(0, |_| PROVIDER_CREDENTIAL_SOURCE_SLOT_BYTES),
        );
        encoded.extend_from_slice(
            match (state, self.source_revision.is_some(), self.source_slot) {
                (ProviderCredentialEnrollmentState::Incomplete, false, None) => {
                    PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC
                }
                (ProviderCredentialEnrollmentState::Complete, false, None) => {
                    PROVIDER_CREDENTIAL_METADATA_MAGIC
                }
                (ProviderCredentialEnrollmentState::Incomplete, true, None) => {
                    PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_V2_MAGIC
                }
                (ProviderCredentialEnrollmentState::Complete, true, None) => {
                    PROVIDER_CREDENTIAL_METADATA_V2_MAGIC
                }
                (ProviderCredentialEnrollmentState::Incomplete, true, Some(_)) => {
                    PROVIDER_CREDENTIAL_SOURCE_INCOMPLETE_MAGIC
                }
                (
                    ProviderCredentialEnrollmentState::Complete,
                    true,
                    Some(source_update::ProviderCredentialSourceSlotVersion {
                        state: source_update::ProviderCredentialSourceSlotState::Pending,
                        ..
                    }),
                ) => PROVIDER_CREDENTIAL_SOURCE_PENDING_MAGIC,
                (
                    ProviderCredentialEnrollmentState::Complete,
                    true,
                    Some(source_update::ProviderCredentialSourceSlotVersion {
                        state: source_update::ProviderCredentialSourceSlotState::Committed,
                        ..
                    }),
                ) => PROVIDER_CREDENTIAL_SOURCE_COMMITTED_MAGIC,
                _ => PROVIDER_CREDENTIAL_INCOMPLETE_METADATA_MAGIC,
            },
        );
        encode_identity(&mut encoded, &self.writer_identity);
        encode_identity(&mut encoded, &self.reader_identity);
        encoded.extend_from_slice(&self.acl_set_digest);
        if let Some(revision) = self.source_revision {
            encoded.extend_from_slice(revision.as_bytes());
        }
        if let Some(source_slot) = self.source_slot {
            encoded.extend_from_slice(&source_slot.generation.to_be_bytes());
            encoded.push(source_slot.slot.tag());
            encoded.extend_from_slice(&[0; 7]);
        }
        encoded
    }

    pub fn is_complete(&self) -> bool {
        self.enrollment_state == ProviderCredentialEnrollmentState::Complete
    }

    pub fn validate_writer_current(&self) -> Result<(), SecureStoreError> {
        validate_current_identity(&self.writer_identity)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }

    pub const fn acl_set_digest(&self) -> [u8; 32] {
        self.acl_set_digest
    }

    pub const fn source_revision(&self) -> Option<ProviderCredentialSourceRevision> {
        self.source_revision
    }

    pub const fn source_slot(
        &self,
    ) -> Option<source_update::ProviderCredentialSourceSlotVersion> {
        self.source_slot
    }

    pub fn access_matches(&self, access: &ProviderCredentialAccessPolicy) -> bool {
        self.writer_identity == *access.writer_identity()
            && self.reader_identity == *access.reader_identity()
    }
}

include!("codec_payload.rs");
