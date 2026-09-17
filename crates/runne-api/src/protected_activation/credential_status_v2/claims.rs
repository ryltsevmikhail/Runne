/// Opaque verified request. `prepare_claims` is accepted by native verification.
pub struct VerifiedProtectedCredentialStatusRequestV2<'a> {
    request: &'a ProtectedCredentialStatusRequestV2,
    prepare_claims: VerifiedProtectedCredentialEnrollmentPrepareV2<'a>,
}

impl VerifiedProtectedCredentialStatusRequestV2<'_> {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.request.sequence
    }

    #[must_use]
    pub const fn prepare_claims(&self) -> &VerifiedProtectedCredentialEnrollmentPrepareV2<'_> {
        &self.prepare_claims
    }

    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        credential_status_request_digest(self.request)
    }
}

/// Native evidence only; it receives verified meaning only through ACK verification.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProtectedCredentialStatusNativeClaimsV2 {
    installation_identity: [u8; 32],
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    installed_generation: u64,
}

impl ProtectedCredentialStatusNativeClaimsV2 {
    pub fn new(
        installation_identity: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        installed_generation: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if installation_identity == [0; 32]
            || release_tuple_digest == [0; 32]
            || qualification_binding_digest == [0; 32]
            || desktop_peer_binding_digest == [0; 32]
            || desktop_supervisor_generation == 0
            || installed_generation == 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            installation_identity,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            installed_generation,
        })
    }
}

/// Opaque claims released only after ACK verification.
pub struct VerifiedProtectedCredentialStatusAckV2<'a> {
    ack: &'a ProtectedCredentialStatusAckV2,
}

impl VerifiedProtectedCredentialStatusAckV2<'_> {
    #[must_use]
    pub const fn installation_identity(&self) -> [u8; 32] {
        self.ack.native.installation_identity
    }

    #[must_use]
    pub const fn release_tuple_digest(&self) -> [u8; 32] {
        self.ack.native.release_tuple_digest
    }

    #[must_use]
    pub const fn qualification_binding_digest(&self) -> [u8; 32] {
        self.ack.native.qualification_binding_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> [u8; 32] {
        self.ack.native.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.ack.native.desktop_supervisor_generation
    }

    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.ack.native.installed_generation
    }
}
