/// Opaque commitment to the broker-transfer key for one launch authority.
///
/// Values are minted only by [`CredentialBrokerTransferAuthenticator`]; no raw
/// key or arbitrary-byte constructor is exposed to callers.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialBrokerTransferCommitment([u8; 32]);

impl CredentialBrokerTransferCommitment {
    const fn from_authenticated_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact committed bytes for daemon-side authority sealing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CredentialBrokerTransferCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBrokerTransferCommitment(<redacted>)")
    }
}

/// Non-authority release/peer commitment carried by native enrollment V3.
///
/// This makes a release tuple, native target, Desktop peer, supervisor
/// generation, and broker-transfer context tamper-evident inside the native
/// transcript. It is *not* a trust decision: the daemon must independently
/// verify the exact release tuple, peer evidence, rendezvous, and expected V3
/// state before admitting a credential operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentLaunchBindingV1 {
    platform: EnrollmentPlatformV1,
    architecture: EnrollmentArchitectureV1,
    installation_identity_digest: [u8; 32],
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    broker_transfer_commitment: CredentialBrokerTransferCommitment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentPlatformV1 {
    Macos = 1,
    Linux = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentArchitectureV1 {
    AppleSiliconAarch64 = 1,
    Arm64 = 2,
    X86_64 = 3,
}

impl ProtectedCredentialEnrollmentLaunchBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn macos_apple_silicon(
        installation_identity_digest: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        broker_transfer_commitment: CredentialBrokerTransferCommitment,
    ) -> Result<Self, LaunchAuthorityError> {
        if installation_identity_digest == [0; 32]
            || release_tuple_digest == [0; 32]
            || qualification_binding_digest == [0; 32]
            || desktop_peer_binding_digest == [0; 32]
            || desktop_supervisor_generation == 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            platform: EnrollmentPlatformV1::Macos,
            architecture: EnrollmentArchitectureV1::AppleSiliconAarch64,
            installation_identity_digest,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            broker_transfer_commitment,
        })
    }

    /// Linux arm64 local enrollment launch binding. The qualification digest
    /// is a self-asserted release consistency digest: local Linux enrollment
    /// carries no hosted qualification evidence (daemon-side admission still
    /// verifies the full signed transcript and the live kernel peer).
    #[allow(clippy::too_many_arguments)]
    pub fn linux_arm64(
        installation_identity_digest: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        broker_transfer_commitment: CredentialBrokerTransferCommitment,
    ) -> Result<Self, LaunchAuthorityError> {
        if installation_identity_digest == [0; 32]
            || release_tuple_digest == [0; 32]
            || qualification_binding_digest == [0; 32]
            || desktop_peer_binding_digest == [0; 32]
            || desktop_supervisor_generation == 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            platform: EnrollmentPlatformV1::Linux,
            architecture: EnrollmentArchitectureV1::Arm64,
            installation_identity_digest,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            broker_transfer_commitment,
        })
    }
    /// Linux x86_64 binding; no hosted qualification is implied.
    #[allow(clippy::too_many_arguments)]
    pub fn linux_x86_64(
        installation_identity_digest: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
        broker_transfer_commitment: CredentialBrokerTransferCommitment,
    ) -> Result<Self, LaunchAuthorityError> {
        let mut binding = Self::linux_arm64(
            installation_identity_digest,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            broker_transfer_commitment,
        )?;
        binding.architecture = EnrollmentArchitectureV1::X86_64;
        Ok(binding)
    }

    #[must_use]
    pub const fn platform(&self) -> EnrollmentPlatformV1 {
        self.platform
    }

    #[must_use]
    pub const fn architecture(&self) -> EnrollmentArchitectureV1 {
        self.architecture
    }

    #[must_use]
    pub const fn installation_identity_digest(&self) -> &[u8; 32] {
        &self.installation_identity_digest
    }

    #[must_use]
    pub const fn release_tuple_digest(&self) -> &[u8; 32] {
        &self.release_tuple_digest
    }

    #[must_use]
    pub const fn qualification_binding_digest(&self) -> &[u8; 32] {
        &self.qualification_binding_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> &[u8; 32] {
        &self.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
    }

    #[must_use]
    pub const fn broker_transfer_commitment(&self) -> &CredentialBrokerTransferCommitment {
        &self.broker_transfer_commitment
    }
}
