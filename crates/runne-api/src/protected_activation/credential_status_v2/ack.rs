/// Authenticated daemon evidence bound to one exact status request.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialStatusAckV2 {
    request_digest: [u8; 32],
    sequence: u64,
    native: ProtectedCredentialStatusNativeClaimsV2,
    proof: [u8; 32],
}

impl ProtectedCredentialStatusAckV2 {
    pub fn new(
        request: &VerifiedProtectedCredentialStatusRequestV2<'_>,
        native: ProtectedCredentialStatusNativeClaimsV2,
    ) -> Result<Self, LaunchAuthorityError> {
        let claims = request.prepare_claims();
        if native.release_tuple_digest != *claims.release_tuple_digest()
            || native.qualification_binding_digest != *claims.qualification_binding_digest()
            || native.desktop_peer_binding_digest != *claims.desktop_peer_binding_digest()
            || native.desktop_supervisor_generation != claims.desktop_supervisor_generation()
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(Self {
            request_digest: request.request_digest(),
            sequence: request.sequence(),
            native,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            CREDENTIAL_STATUS_ACK_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedCredentialStatusRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.request_digest != credential_status_request_digest(request)
            || self.sequence != request.sequence
            || self.native.release_tuple_digest != request.release_tuple_digest
            || self.native.qualification_binding_digest != request.qualification_binding_digest
            || self.native.desktop_peer_binding_digest != request.desktop_peer_binding_digest
            || self.native.desktop_supervisor_generation != request.desktop_supervisor_generation
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            CREDENTIAL_STATUS_ACK_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
        bool::from(proof.ct_eq(&self.proof))
            .then_some(())
            .ok_or(LaunchAuthorityError::ReadinessProofMismatch)
    }

    pub fn verify_exact_view<'a>(
        &'a self,
        request: &ProtectedCredentialStatusRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<VerifiedProtectedCredentialStatusAckV2<'a>, LaunchAuthorityError> {
        self.verify_exact(request, keys)?;
        Ok(VerifiedProtectedCredentialStatusAckV2 { ack: self })
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

    fn unsigned(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn fields(&self, encoder: &mut CborEncoder, proof: bool) {
        encoder.write_map_header(if proof { 11 } else { 10 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V2));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.request_digest);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        for (key, value) in [
            (4, &self.native.installation_identity),
            (5, &self.native.release_tuple_digest),
            (6, &self.native.qualification_binding_digest),
            (7, &self.native.desktop_peer_binding_digest),
        ] {
            write_key(encoder, key);
            encoder.write_byte_string(value);
        }
        write_key(encoder, 8);
        encoder.write_unsigned(self.native.desktop_supervisor_generation);
        write_key(encoder, 9);
        encoder.write_unsigned(self.native.installed_generation);
        if proof {
            write_key(encoder, 10);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl std::fmt::Debug for ProtectedCredentialStatusAckV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedCredentialStatusAckV2(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialStatusAckV2 {
    const MESSAGE_TYPE_ID: u32 = 37;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(11)? != 11 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let request_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let installation_identity = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let release_tuple_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let qualification_binding_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let desktop_peer_binding_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?;
        let desktop_supervisor_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let installed_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 10)?;
        let proof = decode_fixed::<32>(decoder)?;
        if request_digest == [0; 32] || sequence == 0 {
            return Err(DecodeError::UnknownField { key: 2 });
        }
        let native = ProtectedCredentialStatusNativeClaimsV2::new(
            installation_identity,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            installed_generation,
        )
        .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        Ok(Self {
            request_digest,
            sequence,
            native,
            proof,
        })
    }
}

fn credential_status_request_digest(request: &ProtectedCredentialStatusRequestV2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_STATUS_REQUEST_BINDING_DOMAIN_V2);
    hasher.update(PROTOCOL_SCHEMA_VERSION_V2.to_be_bytes());
    hasher.update(request.transcript());
    hasher.finalize().into()
}

/// ```compile_fail
/// use runne_api::{
///     VerifiedProtectedCredentialStatusAckV2, VerifiedProtectedCredentialStatusRequestV2,
/// };
///
/// let _ = VerifiedProtectedCredentialStatusRequestV2 { request: todo!(), prepare_claims: todo!() };
/// let _ = VerifiedProtectedCredentialStatusAckV2 { ack: todo!() };
/// ```
const _: () = ();
