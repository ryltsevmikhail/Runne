impl DeterministicCodec for DaemonEnrollmentLaunchPreludeV1 {
    const MESSAGE_TYPE_ID: u32 = 33;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(14);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        for (key, value) in [
            (2, &self.launch_authority_id[..]),
            (3, &self.desktop_host_instance_id[..]),
        ] {
            write_key(encoder, key);
            encoder.write_byte_string(value);
        }
        write_key(encoder, 4);
        encoder.write_unsigned(self.platform);
        write_key(encoder, 5);
        encoder.write_unsigned(self.architecture);
        for (key, value) in [
            (6, &self.nonce[..]),
            (7, &self.channel_binding[..]),
            (8, &self.publication_key[..]),
            (9, &self.installation_identity_digest[..]),
            (10, &self.desktop_peer_binding_digest[..]),
        ] {
            write_key(encoder, key);
            encoder.write_byte_string(value);
        }
        write_key(encoder, 11);
        encoder.write_unsigned(self.supervisor_generation);
        write_key(encoder, 12);
        encoder.write_unsigned(self.issued_at_unix_millis);
        write_key(encoder, 13);
        encoder.write_unsigned(self.expires_at_unix_millis);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(14)? != 14 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V3)?;
        expect_key(decoder, 2)?;
        let launch = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let platform = decoder.read_unsigned(2)?;
        expect_key(decoder, 5)?;
        let architecture = decoder.read_unsigned(3)?;
        expect_key(decoder, 6)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let channel = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?;
        let publication = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 9)?;
        let installation = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 10)?;
        let peer = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 11)?;
        let generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 12)?;
        let issued = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 13)?;
        let expires = decoder.read_unsigned(u64::MAX)?;
        let prelude = match (platform, architecture) {
            (1, 1) => Self::macos_arm64(
                launch,
                desktop,
                nonce,
                channel,
                publication,
                installation,
                peer,
                generation,
                issued,
                expires,
            ),
            (2, 2) => Self::linux_arm64(
                launch,
                desktop,
                nonce,
                channel,
                publication,
                installation,
                peer,
                generation,
                issued,
                expires,
            ),
            (2, 3) => Self::linux_x86_64(
                launch,
                desktop,
                nonce,
                channel,
                publication,
                installation,
                peer,
                generation,
                issued,
                expires,
            ),
            _ => return Err(DecodeError::UnknownField { key: 4 }),
        };
        prelude.map_err(|_| DecodeError::UnknownField { key: 2 })
    }
}
