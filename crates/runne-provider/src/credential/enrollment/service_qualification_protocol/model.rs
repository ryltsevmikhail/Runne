use zeroize::Zeroizing;

pub(super) const COMMON_BYTES: usize = 352;

/// Strict request kinds accepted by the disabled qualification profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceQualificationRequestKind {
    /// Reserves one bounded qualification transfer.
    Start,
    /// Carries one contiguous release fragment.
    Chunk,
    /// Carries the complete bounded admission bundle.
    Finalize,
}

impl ServiceQualificationRequestKind {
    pub(super) const fn wire(self) -> u8 {
        match self {
            Self::Start => 1,
            Self::Chunk => 2,
            Self::Finalize => 3,
        }
    }
}

/// Closed authenticated rejection reasons for the qualification profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceQualificationRejectionCode {
    /// The authenticated request is not permitted.
    Denied,
    /// The bounded receiver has no available verifier capacity.
    Busy,
    /// The authenticated request is no longer fresh.
    Expired,
    /// The receiver cannot currently allocate or serve the request.
    Unavailable,
}

impl ServiceQualificationRejectionCode {
    pub(super) const fn wire(self) -> u8 {
        match self {
            Self::Denied => 1,
            Self::Busy => 2,
            Self::Expired => 3,
            Self::Unavailable => 4,
        }
    }
}

/// Typed common facts retained for the future consuming core stage.
#[must_use]
pub struct ServiceQualificationCommon {
    /// Service epoch binding.
    pub service_epoch: [u8; 16],
    /// UUIDv7 protected-session identifier.
    pub protected_session_id: [u8; 16],
    /// Daemon authority generation.
    pub daemon_authority_generation: u64,
    /// Runtime generation.
    pub runtime_generation: u64,
    /// Desktop supervisor generation.
    pub supervisor_generation: u64,
    /// Installed release generation.
    pub installed_generation: u64,
    /// Installation owner binding.
    pub installation_owner: [u8; 32],
    /// Release binding digest.
    pub release_binding: [u8; 32],
    /// Registration challenge nonce.
    pub challenge_nonce: [u8; 16],
    /// Registration join attempt.
    pub join_attempt: u64,
    /// Registration expiry in Unix milliseconds.
    pub registration_expires_at_unix_millis: u64,
    /// Monotonic service request sequence.
    pub sequence: u64,
    /// Transfer identifier.
    pub transfer_id: [u8; 16],
    /// Credential operation identifier.
    pub operation_id: [u8; 16],
    /// Provider ticket attempt.
    pub provider_ticket_attempt: u64,
    /// Provider ticket binding digest.
    pub provider_ticket_binding_digest: [u8; 32],
    /// Qualification fault-ticket SHA-256.
    pub qualification_fault_ticket_sha256: [u8; 32],
    /// Release-frame SHA-256.
    pub release_frame_sha256: [u8; 32],
    /// Admission-bundle SHA-256.
    pub admission_bundle_sha256: [u8; 32],
    /// Qualification issue time in Unix milliseconds.
    pub issued_at_unix_millis: u64,
    /// Qualification expiry time in Unix milliseconds.
    pub expires_at_unix_millis: u64,
}

impl ServiceQualificationCommon {
    pub(super) fn from_wire(bytes: [u8; COMMON_BYTES]) -> Self {
        Self {
            service_epoch: bytes_at(&bytes, 0),
            protected_session_id: bytes_at(&bytes, 16),
            daemon_authority_generation: u64_at(&bytes, 32),
            runtime_generation: u64_at(&bytes, 40),
            supervisor_generation: u64_at(&bytes, 48),
            installed_generation: u64_at(&bytes, 56),
            installation_owner: bytes_at(&bytes, 64),
            release_binding: bytes_at(&bytes, 96),
            challenge_nonce: bytes_at(&bytes, 128),
            join_attempt: u64_at(&bytes, 144),
            registration_expires_at_unix_millis: u64_at(&bytes, 152),
            sequence: u64_at(&bytes, 160),
            transfer_id: bytes_at(&bytes, 168),
            operation_id: bytes_at(&bytes, 184),
            provider_ticket_attempt: u64_at(&bytes, 200),
            provider_ticket_binding_digest: bytes_at(&bytes, 208),
            qualification_fault_ticket_sha256: bytes_at(&bytes, 240),
            release_frame_sha256: bytes_at(&bytes, 272),
            admission_bundle_sha256: bytes_at(&bytes, 304),
            issued_at_unix_millis: u64_at(&bytes, 336),
            expires_at_unix_millis: u64_at(&bytes, 344),
        }
    }

    pub(super) fn into_wire_bytes(self) -> [u8; COMMON_BYTES] {
        let mut bytes = [0; COMMON_BYTES];
        bytes[..16].copy_from_slice(&self.service_epoch);
        bytes[16..32].copy_from_slice(&self.protected_session_id);
        for (offset, value) in [
            (32, self.daemon_authority_generation),
            (40, self.runtime_generation),
            (48, self.supervisor_generation),
            (56, self.installed_generation),
            (144, self.join_attempt),
            (152, self.registration_expires_at_unix_millis),
            (160, self.sequence),
            (200, self.provider_ticket_attempt),
            (336, self.issued_at_unix_millis),
            (344, self.expires_at_unix_millis),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [
            (64, &self.installation_owner[..]),
            (96, &self.release_binding[..]),
            (128, &self.challenge_nonce[..]),
            (168, &self.transfer_id[..]),
            (184, &self.operation_id[..]),
            (208, &self.provider_ticket_binding_digest[..]),
            (240, &self.qualification_fault_ticket_sha256[..]),
            (272, &self.release_frame_sha256[..]),
            (304, &self.admission_bundle_sha256[..]),
        ] {
            bytes[offset..offset + value.len()].copy_from_slice(value);
        }
        bytes
    }
}

/// Closed, move-only kind-specific request contents.
#[must_use]
pub enum ServiceQualificationRequestPayload {
    /// Fixed Start commitments.
    Start {
        /// Complete release-frame byte length.
        release_frame_len: u32,
        /// Required exact chunk width.
        chunk_bytes: u16,
        /// Exact total fragment count.
        chunk_count: u16,
        /// Complete admission-bundle byte length.
        admission_bundle_len: u32,
    },
    /// One bounded release fragment.
    Chunk {
        /// Zero-based fragment index.
        chunk_index: u16,
        /// Exact total fragment count.
        chunk_count: u16,
        /// Exact release-frame byte offset.
        offset: u32,
        /// Owned bounded fragment bytes.
        bytes: Zeroizing<Vec<u8>>,
    },
    /// Complete bounded admission bundle.
    Finalize {
        /// Complete release-frame byte length.
        release_frame_len: u32,
        /// Exact total fragment count.
        chunk_count: u16,
        /// Owned bounded admission-bundle bytes.
        admission_bundle: Zeroizing<Vec<u8>>,
    },
}

impl ServiceQualificationRequestPayload {
    pub(super) const fn kind(&self) -> ServiceQualificationRequestKind {
        match self {
            Self::Start { .. } => ServiceQualificationRequestKind::Start,
            Self::Chunk { .. } => ServiceQualificationRequestKind::Chunk,
            Self::Finalize { .. } => ServiceQualificationRequestKind::Finalize,
        }
    }
}

/// Opaque, move-only request with typed facts and no raw-frame accessor.
#[must_use]
pub struct ServiceQualificationRequest {
    common: ServiceQualificationCommon,
    payload: ServiceQualificationRequestPayload,
}

impl ServiceQualificationRequest {
    pub(super) const fn new(
        common: ServiceQualificationCommon,
        payload: ServiceQualificationRequestPayload,
    ) -> Self {
        Self { common, payload }
    }

    /// Returns the closed request discriminator without exposing a raw frame.
    pub const fn kind(&self) -> ServiceQualificationRequestKind {
        self.payload.kind()
    }

    /// Consumes the request into typed facts for the future core stage.
    pub fn into_parts(
        self,
    ) -> (
        ServiceQualificationCommon,
        ServiceQualificationRequestPayload,
    ) {
        (self.common, self.payload)
    }

    pub(super) fn into_reply_parts(self) -> ([u8; COMMON_BYTES], ServiceQualificationRequestKind) {
        (self.common.into_wire_bytes(), self.payload.kind())
    }
}

/// Opaque, move-only encoded nonfinal reply frame.
#[must_use]
pub struct ServiceQualificationReplyFrame(#[allow(dead_code)] pub(super) Zeroizing<Vec<u8>>);

impl ServiceQualificationReplyFrame {
    pub(super) const fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(super) fn test_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn bytes_at<const N: usize>(source: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&source[offset..offset + N]);
    value
}

fn u64_at(source: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes_at(source, offset))
}
