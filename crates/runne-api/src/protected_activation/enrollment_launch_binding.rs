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
}

impl fmt::Debug for CredentialBrokerTransferCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBrokerTransferCommitment(<redacted>)")
    }
}

/// Non-authority release/peer commitment carried by native enrollment V3.
///
/// This makes a release tuple, Apple-Silicon target, Desktop peer, supervisor
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentArchitectureV1 {
    AppleSiliconAarch64 = 1,
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

fn encode_enrollment_binding(
    encoder: &mut CborEncoder,
    binding: &ProtectedCredentialEnrollmentLaunchBindingV1,
) {
    encoder.write_map_header(8);
    write_key(encoder, 1);
    encoder.write_unsigned(binding.platform as u64);
    write_key(encoder, 2);
    encoder.write_unsigned(binding.architecture as u64);
    for (key, value) in [
        (3, &binding.installation_identity_digest),
        (4, &binding.release_tuple_digest),
        (5, &binding.qualification_binding_digest),
        (6, &binding.desktop_peer_binding_digest),
    ] {
        write_key(encoder, key);
        encoder.write_byte_string(value);
    }
    write_key(encoder, 7);
    encoder.write_unsigned(binding.desktop_supervisor_generation);
    write_key(encoder, 8);
    encoder.write_byte_string(&binding.broker_transfer_commitment.0);
}

fn decode_enrollment_binding(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedCredentialEnrollmentLaunchBindingV1, DecodeError> {
    if decoder.read_map_header(8)? != 8 {
        return Err(DecodeError::UnknownField { key: 12 });
    }
    expect_key(decoder, 1)?;
    if decoder.read_unsigned(1)? != EnrollmentPlatformV1::Macos as u64 {
        return Err(DecodeError::UnknownField { key: 1 });
    }
    expect_key(decoder, 2)?;
    if decoder.read_unsigned(1)? != EnrollmentArchitectureV1::AppleSiliconAarch64 as u64 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 3)?;
    let installation = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 4)?;
    let release = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 5)?;
    let qualification = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 6)?;
    let peer = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 7)?;
    let generation = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 8)?;
    let commitment = decode_fixed::<32>(decoder)?;
    ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        installation,
        release,
        qualification,
        peer,
        generation,
        CredentialBrokerTransferCommitment::from_authenticated_bytes(commitment),
    )
    .map_err(|_| DecodeError::UnknownField { key: 12 })
}
