
/// One-time protected bootstrap ticket for a rotated HTTP session.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewTicketV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    sequence: u64,
    nonce: [u8; 32],
    next_session_id: [u8; 16],
    bootstrap_ticket: [u8; 32],
    issued_at_monotonic_millis: u64,
    expires_at_monotonic_millis: u64,
    proof: [u8; 32],
}

impl ProtectedRenewTicketV1 {
    /// Builds an unsigned ticket for the exact accepted renewal.
    pub fn new(
        request: &ProtectedRenewRequestV1,
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
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
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

    /// Signs the exact canonical ticket transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies the ticket against the exact accepted renewal.
    pub fn verify_exact(
        &self,
        request: &ProtectedRenewRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.owned_launch != request.owned_launch
            || self.sequence != request.sequence
            || self.nonce != request.nonce
        {
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
        let expected = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn next_session_id(&self) -> &[u8; 16] {
        &self.next_session_id
    }

    /// Copies the one-time bootstrap ticket into a zeroizing owner.
    #[must_use]
    pub fn bootstrap_ticket(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bootstrap_ticket)
    }

    pub const fn issued_at_monotonic_millis(&self) -> u64 {
        self.issued_at_monotonic_millis
    }

    pub const fn expires_at_monotonic_millis(&self) -> u64 {
        self.expires_at_monotonic_millis
    }

    /// Returns the ownership tuple after the ticket's session rotation.
    #[must_use]
    pub fn next_owned_launch(&self) -> ProtectedOwnedLaunchV1 {
        ProtectedOwnedLaunchV1::new(
            self.owned_launch.launch_authority_id,
            self.owned_launch.desktop_host_instance_id,
            self.owned_launch.executable.clone(),
            self.owned_launch.profile.clone(),
            self.owned_launch.stable.clone(),
            self.owned_launch.daemon_instance_id,
            self.owned_launch.launch_generation,
            self.next_session_id,
        )
        .expect("validated renewal ticket has a valid next session")
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
        encode_owned_launch(encoder, &self.owned_launch);
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

impl fmt::Debug for ProtectedRenewTicketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewTicketV1")
            .field("sequence", &self.sequence)
            .field(
                "expires_at_monotonic_millis",
                &self.expires_at_monotonic_millis,
            )
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl Drop for ProtectedRenewTicketV1 {
    fn drop(&mut self) {
        self.bootstrap_ticket.zeroize();
    }
}
