/// Daemon-first V3 launch evidence; decoding it grants no launch authority.
#[derive(Clone, Eq, PartialEq)]
pub struct DaemonEnrollmentLaunchPreludeV1 {
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    platform: u64,
    architecture: u64,
    nonce: [u8; 32],
    channel_binding: [u8; 32],
    publication_key: [u8; 32],
    installation_identity_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    supervisor_generation: u64,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl DaemonEnrollmentLaunchPreludeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn macos_arm64(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        nonce: [u8; 32],
        channel_binding: [u8; 32],
        publication_key: [u8; 32],
        installation_identity_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        supervisor_generation: u64,
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || [
                nonce,
                channel_binding,
                publication_key,
                installation_identity_digest,
                desktop_peer_binding_digest,
            ]
            .contains(&[0; 32])
            || supervisor_generation == 0
            || issued_at_unix_millis == 0
            || expires_at_unix_millis <= issued_at_unix_millis
            || expires_at_unix_millis - issued_at_unix_millis > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            launch_authority_id,
            desktop_host_instance_id,
            platform: 1,
            architecture: 1,
            nonce,
            channel_binding,
            publication_key,
            installation_identity_digest,
            desktop_peer_binding_digest,
            supervisor_generation,
            issued_at_unix_millis,
            expires_at_unix_millis,
        })
    }

    /// Linux arm64 local enrollment prelude; the transcript layout is shared,
    /// only the platform/architecture discriminators differ.
    #[allow(clippy::too_many_arguments)]
    pub fn linux_arm64(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        nonce: [u8; 32],
        channel_binding: [u8; 32],
        publication_key: [u8; 32],
        installation_identity_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        supervisor_generation: u64,
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        let mut prelude = Self::macos_arm64(
            launch_authority_id,
            desktop_host_instance_id,
            nonce,
            channel_binding,
            publication_key,
            installation_identity_digest,
            desktop_peer_binding_digest,
            supervisor_generation,
            issued_at_unix_millis,
            expires_at_unix_millis,
        )?;
        prelude.platform = 2;
        prelude.architecture = 2;
        Ok(prelude)
    }

    /// Linux x86_64 prelude with the same authenticated transcript layout.
    #[allow(clippy::too_many_arguments)]
    pub fn linux_x86_64(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        nonce: [u8; 32],
        channel_binding: [u8; 32],
        publication_key: [u8; 32],
        installation_identity_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        supervisor_generation: u64,
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        let mut prelude = Self::linux_arm64(
            launch_authority_id,
            desktop_host_instance_id,
            nonce,
            channel_binding,
            publication_key,
            installation_identity_digest,
            desktop_peer_binding_digest,
            supervisor_generation,
            issued_at_unix_millis,
            expires_at_unix_millis,
        )?;
        prelude.architecture = 3;
        Ok(prelude)
    }

    #[must_use]
    pub const fn architecture(&self) -> u64 {
        self.architecture
    }

    #[must_use]
    pub const fn platform(&self) -> u64 {
        self.platform
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.launch_authority_id
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.desktop_host_instance_id
    }

    #[must_use]
    pub const fn installation_identity_digest(&self) -> &[u8; 32] {
        &self.installation_identity_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> &[u8; 32] {
        &self.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation
    }

    /// Daemon-generated rendezvous binding for the exact writer channel.
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// Publication key that later verifies the inert daemon publication.
    #[must_use]
    pub const fn publication_key(&self) -> [u8; 32] {
        self.publication_key
    }

    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if now_unix_millis < self.issued_at_unix_millis
            || now_unix_millis > self.expires_at_unix_millis
        {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_v3_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_v3_frame(frame)
    }

    pub(crate) fn canonical_transcript(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode(&mut encoder)
            .expect("infallible prelude encoding");
        encoder.into_bytes()
    }
}

impl fmt::Debug for DaemonEnrollmentLaunchPreludeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DaemonEnrollmentLaunchPreludeV1(<redacted>)")
    }
}
