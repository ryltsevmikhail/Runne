/// One-time V3 bootstrap ticket; stored ticket material is zeroized on drop.
///
/// ```compile_fail
/// use runne_api::ProtectedCredentialEnrollmentRenewTicketV3;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ProtectedCredentialEnrollmentRenewTicketV3>();
/// ```
#[derive(Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentRenewTicketV3 {
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    sequence: u64,
    nonce: [u8; 32],
    next_session: [u8; 16],
    bootstrap_ticket: Zeroizing<[u8; 32]>,
    issued: u64,
    expires: u64,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentRenewTicketV3 {
    pub fn new(
        request: &ProtectedCredentialEnrollmentRenewRequestV3,
        next_session: [u8; 16],
        bootstrap_ticket: [u8; 32],
        issued: u64,
        expires: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&next_session).is_err()
            || next_session == *request.owned.session_id()
            || next_session == request.owned.core.daemon_id
            || bootstrap_ticket == [0; 32]
            || expires <= issued
            || expires.saturating_sub(issued) > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::RenewalUnavailable);
        }
        Ok(Self {
            owned: request.owned.clone(),
            sequence: request.sequence,
            nonce: request.nonce,
            next_session,
            bootstrap_ticket: Zeroizing::new(bootstrap_ticket),
            issued,
            expires,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
    }

    pub fn verify_exact_at<'a>(
        &'a self,
        request: &ProtectedCredentialEnrollmentRenewRequestV3,
        now: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<VerifiedProtectedCredentialEnrollmentRenewTicketV3<'a>, LaunchAuthorityError> {
        self.owned.exact(&request.owned)?;
        if self.sequence != request.sequence
            || self.nonce != request.nonce
            || *self.bootstrap_ticket == [0; 32]
            || self.expires <= self.issued
            || now < self.issued
            || now > self.expires
        {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let expected_proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            RENEW_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
        if !bool::from(expected_proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(VerifiedProtectedCredentialEnrollmentRenewTicketV3 { ticket: self })
    }

    #[must_use]
    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.next_session
    }

    #[must_use]
    pub const fn issued_at_monotonic_millis(&self) -> u64 {
        self.issued
    }

    #[must_use]
    pub const fn expires_at_monotonic_millis(&self) -> u64 {
        self.expires
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_v3_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_v3_frame(frame)
    }

    fn unsigned(&self) -> Zeroizing<Vec<u8>> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        Zeroizing::new(encoder.into_bytes())
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 12 } else { 11 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        write_key(encoder, 2);
        encode_owned_core(encoder, &self.owned.core);
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.owned.provider);
        write_key(encoder, 4);
        encode_enrollment_binding(encoder, &self.owned.enrollment);
        write_key(encoder, 5);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 6);
        encoder.write_byte_string(&self.nonce);
        write_key(encoder, 7);
        encoder.write_byte_string(&self.next_session);
        write_key(encoder, 8);
        encoder.write_byte_string(self.bootstrap_ticket.as_ref());
        write_key(encoder, 9);
        encoder.write_unsigned(self.issued);
        write_key(encoder, 10);
        encoder.write_unsigned(self.expires);
        if include_proof {
            write_key(encoder, 11);
            encoder.write_byte_string(&self.proof);
        }
    }
}

/// Freshness-verified view that alone can reveal a renewal bootstrap ticket.
pub struct VerifiedProtectedCredentialEnrollmentRenewTicketV3<'a> {
    ticket: &'a ProtectedCredentialEnrollmentRenewTicketV3,
}

impl VerifiedProtectedCredentialEnrollmentRenewTicketV3<'_> {
    #[must_use]
    pub fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.ticket.bootstrap_ticket)
    }

    #[must_use]
    pub fn next_owned_launch(&self) -> ProtectedCredentialEnrollmentOwnedLaunchV3 {
        ProtectedCredentialEnrollmentOwnedLaunchV3 {
            core: self
                .ticket
                .owned
                .core
                .next(self.ticket.next_session)
                .expect("verified V3 ticket"),
            provider: self.ticket.owned.provider.clone(),
            enrollment: self.ticket.owned.enrollment.clone(),
        }
    }

    #[must_use]
    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.ticket.next_session
    }
}

impl Drop for ProtectedCredentialEnrollmentRenewTicketV3 {
    fn drop(&mut self) {
        self.bootstrap_ticket.zeroize();
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentRenewTicketV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentRenewTicketV3(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialEnrollmentRenewTicketV3 {
    const MESSAGE_TYPE_ID: u32 = 30;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(12)? != 12 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V3)?;
        expect_key(decoder, 2)?;
        let core = decode_owned_core(decoder)?;
        expect_key(decoder, 3)?;
        let provider = decode_provider_binding(decoder)?;
        if require_credential_provider(&provider).is_err() {
            return Err(DecodeError::UnknownField { key: 3 });
        }
        expect_key(decoder, 4)?;
        let enrollment = decode_enrollment_binding(decoder)?;
        expect_key(decoder, 5)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 6)?;
        let nonce = decode_fixed::<32>(decoder)?;
        let request = ProtectedCredentialEnrollmentRenewRequestV3::new(
            ProtectedCredentialEnrollmentOwnedLaunchV3 {
                core,
                provider,
                enrollment,
            },
            sequence,
            nonce,
        )
        .map_err(|_| DecodeError::UnknownField { key: 5 })?;
        expect_key(decoder, 7)?;
        let next_session = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 8)?;
        let bootstrap_ticket = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 9)?;
        let issued = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 10)?;
        let expires = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 11)?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(&request, next_session, bootstrap_ticket, issued, expires)
            .map_err(|_| DecodeError::UnknownField { key: 7 })?;
        value.proof = proof;
        Ok(value)
    }
}
