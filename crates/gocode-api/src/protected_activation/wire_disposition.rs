
impl ProtectedRenewTicketV2 {
    pub fn new(
        request: &ProtectedRenewRequestV2,
        next_session_id: [u8; 16],
        bootstrap_ticket: [u8; 32],
        issued_at_monotonic_millis: u64,
        expires_at_monotonic_millis: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&next_session_id).is_err()
            || next_session_id == *request.owned_launch.session_id()
            || next_session_id == *request.owned_launch.daemon_instance_id()
            || bootstrap_ticket == [0; 32]
            || expires_at_monotonic_millis <= issued_at_monotonic_millis
            || expires_at_monotonic_millis.saturating_sub(issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch: request.owned_launch.clone(),
            sequence: request.sequence,
            nonce: request.nonce,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedRenewRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(&request.owned_launch)?;
        if self.sequence != request.sequence || self.nonce != request.nonce {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        if validate_uuid_v7_bytes(&self.next_session_id).is_err()
            || self.next_session_id == *self.owned_launch.session_id()
            || self.next_session_id == *self.owned_launch.daemon_instance_id()
            || self.bootstrap_ticket == [0; 32]
            || self.expires_at_monotonic_millis <= self.issued_at_monotonic_millis
            || self
                .expires_at_monotonic_millis
                .saturating_sub(self.issued_at_monotonic_millis)
                > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        let expected = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.next_session_id
    }

    #[must_use]
    pub fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bootstrap_ticket)
    }

    #[must_use]
    pub const fn issued_at_monotonic_millis(&self) -> u64 {
        self.issued_at_monotonic_millis
    }

    #[must_use]
    pub const fn expires_at_monotonic_millis(&self) -> u64 {
        self.expires_at_monotonic_millis
    }

    #[must_use]
    pub fn next_owned_launch(&self) -> ProtectedOwnedLaunchV2 {
        let base = &self.owned_launch.compatibility_owned_launch;
        let next = ProtectedOwnedLaunchV1::new(
            base.launch_authority_id,
            base.desktop_host_instance_id,
            base.executable.clone(),
            base.profile.clone(),
            base.stable.clone(),
            base.daemon_instance_id,
            base.launch_generation,
            self.next_session_id,
        )
        .expect("validated V2 ticket has a valid next session");
        ProtectedOwnedLaunchV2::new(next, self.owned_launch.provider_binding.clone())
            .expect("validated V2 ticket retains a valid provider binding")
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 10 } else { 9 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        write_key(encoder, 5);
        encoder.write_byte_string(&self.next_session_id);
        write_key(encoder, 6);
        encoder.write_byte_string(&self.bootstrap_ticket);
        write_key(encoder, 7);
        encoder.write_unsigned(self.issued_at_monotonic_millis);
        write_key(encoder, 8);
        encoder.write_unsigned(self.expires_at_monotonic_millis);
        if include_proof {
            write_key(encoder, 9);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewTicketV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewTicketV2")
            .field("sequence", &self.sequence)
            .field(
                "expires_at_monotonic_millis",
                &self.expires_at_monotonic_millis,
            )
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl Drop for ProtectedRenewTicketV2 {
    fn drop(&mut self) {
        self.bootstrap_ticket.zeroize();
    }
}

impl DeterministicCodec for ProtectedRenewTicketV2 {
    const MESSAGE_TYPE_ID: u32 = 24;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(10)? != 10 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let next_session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 6)?;
        let bootstrap_ticket = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let issued_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 8)?;
        let expires_at_monotonic_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let proof = decode_fixed::<32>(decoder)?;
        let request = ProtectedRenewRequestV2 {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            sequence,
            nonce,
            proof: [1; 32],
        };
        let mut value = Self::new(
            &request,
            next_session_id,
            bootstrap_ticket,
            issued_at_monotonic_millis,
            expires_at_monotonic_millis,
        )
        .map_err(|_| DecodeError::UnknownField { key: 7 })?;
        value.proof = proof;
        Ok(value)
    }
}

/// HMAC-authenticated V2 shutdown request for an exact provider-bound launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    proof: [u8; 32],
}
