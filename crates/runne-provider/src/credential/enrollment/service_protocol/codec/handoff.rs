use zeroize::Zeroizing;

use crate::credential::enrollment::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialEnrollmentError, CredentialOperationAction, CredentialWriterEffectAuthority,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
};

use super::super::{
    AuthorizedCredentialLegacyRead, CredentialMutationGrant, CredentialWriterBrokerHandoffFrame,
    CredentialWriterConsumeRequest, CredentialWriterServiceBindingHandoff,
};
use super::{
    CredentialServiceEndpointRole, CredentialServiceProtocolCodec, HEADER, byte, decode_role,
    frame, kind_role, mutation_binding, payload, take, take_mutation_binding,
};

const HANDOFF_KIND: u8 = 6;

impl CredentialServiceProtocolCodec {
    /// Encodes a raw grant and its exact plan half into one opaque writer handoff.
    pub fn encode_writer_broker_handoff(
        binding: CredentialWriterServiceBindingHandoff,
        grant: CredentialMutationGrant,
    ) -> Result<CredentialWriterBrokerHandoffFrame, CredentialEnrollmentError> {
        encode(binding, grant)
    }

    /// Strict-decodes and authenticates one handoff without exposing grant bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_authenticated_writer_broker_handoff(
        bytes: &[u8],
        authorization: ClaimedWriterAuthorization,
        effects: &CredentialWriterEffectAuthority,
        channel: &BrokerChannelBinding,
        claim_binding: CredentialBindingDigest,
        pending: PendingCredentialSecretOpening,
        envelope: SealedCredentialEnvelope,
    ) -> Result<CredentialWriterConsumeRequest, CredentialEnrollmentError> {
        decode_authenticated(
            bytes,
            authorization,
            effects,
            channel,
            claim_binding,
            pending,
            envelope,
        )
    }

    /// Authenticates one secretless revoke/cleanup handoff.
    pub fn decode_authenticated_writer_control_handoff(
        bytes: &[u8],
        authorization: ClaimedWriterAuthorization,
        effects: &CredentialWriterEffectAuthority,
        channel: &BrokerChannelBinding,
        claim_binding: CredentialBindingDigest,
    ) -> Result<CredentialWriterConsumeRequest, CredentialEnrollmentError> {
        let (binding, grant) = decode_handoff(bytes)?;
        effects.authorize(
            authorization,
            binding.command.clone(),
            claim_binding,
            channel,
        )?;
        CredentialWriterConsumeRequest::from_authenticated_control_parts(binding, grant)
    }

    /// Authenticates one legacy migration before reading its exact source item.
    pub fn decode_authenticated_writer_legacy_handoff(
        bytes: &[u8],
        authorization: ClaimedWriterAuthorization,
        effects: &CredentialWriterEffectAuthority,
        channel: &BrokerChannelBinding,
        claim_binding: CredentialBindingDigest,
        load_material: impl FnOnce(
            AuthorizedCredentialLegacyRead,
        ) -> Result<
            super::super::CredentialLegacySourceMaterial,
            CredentialEnrollmentError,
        >,
    ) -> Result<CredentialWriterConsumeRequest, CredentialEnrollmentError> {
        let (binding, grant) = decode_handoff(bytes)?;
        if binding.command.action() != CredentialOperationAction::MigrateLegacy {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        let command = effects.authorize(
            authorization,
            binding.command.clone(),
            claim_binding,
            channel,
        )?;
        let material = load_material(AuthorizedCredentialLegacyRead::new(
            command,
            claim_binding,
            channel.digest(),
            effects,
        ))?;
        CredentialWriterConsumeRequest::from_authenticated_legacy_parts(binding, grant, material)
    }
}

fn encode(
    binding: CredentialWriterServiceBindingHandoff,
    grant: CredentialMutationGrant,
) -> Result<CredentialWriterBrokerHandoffFrame, CredentialEnrollmentError> {
    if !binding.0.grant_digest.ct_matches(grant.digest()) {
        return Err(CredentialEnrollmentError::InvalidEvidence);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    kind_role(
        &mut bytes,
        HANDOFF_KIND,
        CredentialServiceEndpointRole::Writer,
    );
    mutation_binding(&mut bytes, &binding.0)?;
    bytes.extend_from_slice(grant.wire_bytes());
    Ok(CredentialWriterBrokerHandoffFrame(frame(
        bytes,
        super::CredentialServiceProtocolCodec::MAX_FRAME_BYTES,
    )?))
}

#[allow(clippy::too_many_arguments)]
fn decode_authenticated(
    bytes: &[u8],
    authorization: ClaimedWriterAuthorization,
    effects: &CredentialWriterEffectAuthority,
    channel: &BrokerChannelBinding,
    claim_binding: CredentialBindingDigest,
    pending: PendingCredentialSecretOpening,
    envelope: SealedCredentialEnvelope,
) -> Result<CredentialWriterConsumeRequest, CredentialEnrollmentError> {
    let (binding, grant) = decode_handoff(bytes)?;
    let opening = effects.authorize_secret_opening(
        authorization,
        binding.command.clone(),
        claim_binding,
        channel,
    )?;
    let material = pending
        .open_after_claim(opening, channel, envelope)?
        .into_service_material()?;
    CredentialWriterConsumeRequest::from_authenticated_parts(binding, grant, material)
}

fn decode_handoff(
    bytes: &[u8],
) -> Result<
    (
        super::super::request::CredentialRuntimeMutationBinding,
        CredentialMutationGrant,
    ),
    CredentialEnrollmentError,
> {
    let bytes = payload(bytes, CredentialServiceProtocolCodec::MAX_FRAME_BYTES)?;
    let mut at = HEADER;
    if byte(bytes, &mut at)? != HANDOFF_KIND
        || decode_role(byte(bytes, &mut at)?)? != CredentialServiceEndpointRole::Writer
    {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    let binding = take_mutation_binding(bytes, &mut at)?;
    let grant = CredentialMutationGrant::from_wire(take(bytes, &mut at)?)?;
    if at != bytes.len() || !binding.grant_digest.ct_matches(grant.digest()) {
        return Err(CredentialEnrollmentError::InvalidFrame);
    }
    Ok((binding, grant))
}
