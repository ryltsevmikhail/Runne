/// Daemon-first V3 launch evidence; decoding it grants no launch authority.
#[derive(Clone, Eq, PartialEq)]
pub struct DaemonEnrollmentLaunchPreludeV1 {
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

    #[must_use]
    pub const fn launch_authority_id(&self) -> [u8; 16] { self.launch_authority_id }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> [u8; 16] { self.desktop_host_instance_id }

    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if now_unix_millis < self.issued_at_unix_millis || now_unix_millis > self.expires_at_unix_millis {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> { encode_v3_frame(self) }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> { decode_v3_frame(frame) }

    pub(crate) fn canonical_transcript(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode(&mut encoder).expect("infallible prelude encoding");
        encoder.into_bytes()
    }
}

impl fmt::Debug for DaemonEnrollmentLaunchPreludeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DaemonEnrollmentLaunchPreludeV1(<redacted>)")
    }
}

impl DeterministicCodec for DaemonEnrollmentLaunchPreludeV1 {
    const MESSAGE_TYPE_ID: u32 = 33;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(14);
        write_key(encoder, 0); encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1); encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        for (key, value) in [(2, &self.launch_authority_id[..]), (3, &self.desktop_host_instance_id[..])] {
            write_key(encoder, key); encoder.write_byte_string(value);
        }
        write_key(encoder, 4); encoder.write_unsigned(1);
        write_key(encoder, 5); encoder.write_unsigned(1);
        for (key, value) in [
            (6, &self.nonce[..]), (7, &self.channel_binding[..]), (8, &self.publication_key[..]),
            (9, &self.installation_identity_digest[..]), (10, &self.desktop_peer_binding_digest[..]),
        ] { write_key(encoder, key); encoder.write_byte_string(value); }
        write_key(encoder, 11); encoder.write_unsigned(self.supervisor_generation);
        write_key(encoder, 12); encoder.write_unsigned(self.issued_at_unix_millis);
        write_key(encoder, 13); encoder.write_unsigned(self.expires_at_unix_millis);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(14)? != 14 { return Err(DecodeError::UnknownMessageType { type_id }); }
        expect_key(decoder, 0)?; expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V3)?;
        expect_key(decoder, 2)?; let launch = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?; let desktop = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?; if decoder.read_unsigned(1)? != 1 { return Err(DecodeError::UnknownField { key: 4 }); }
        expect_key(decoder, 5)?; if decoder.read_unsigned(1)? != 1 { return Err(DecodeError::UnknownField { key: 5 }); }
        expect_key(decoder, 6)?; let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?; let channel = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?; let publication = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 9)?; let installation = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 10)?; let peer = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 11)?; let generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 12)?; let issued = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 13)?; let expires = decoder.read_unsigned(u64::MAX)?;
        Self::macos_arm64(launch, desktop, nonce, channel, publication, installation, peer, generation, issued, expires)
            .map_err(|_| DecodeError::UnknownField { key: 2 })
    }
}
