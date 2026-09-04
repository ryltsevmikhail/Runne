use std::time::{Duration, Instant};

use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation, CredentialServiceWriterPort,
    CredentialServiceWriterRequest,
};
use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
    CredentialServiceRequestContext, CredentialWriterBrokerHandoffFrame,
    CredentialWriterEffectAuthority, PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
use runne_secure_store::BrokeredProviderCredentialLegacySource;

use super::CliError;

#[allow(clippy::too_many_arguments)]
pub(super) fn consume_service_pair(
    effects: &CredentialWriterEffectAuthority,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
    pending: PendingCredentialSecretOpening,
    envelope: SealedCredentialEnvelope,
) -> Result<(), CliError> {
    let port = runne_macos_xpc::CredentialServiceWriterXpcClient::connect(configuration)
        .map_err(|_| CliError::CredentialOperation)?;
    consume_service_pair_with_port(
        &port,
        effects,
        handoff,
        authorization,
        channel,
        binding,
        pending,
        envelope,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn consume_service_pair_with_port(
    port: &impl CredentialServiceWriterPort,
    effects: &CredentialWriterEffectAuthority,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
    pending: PendingCredentialSecretOpening,
    envelope: SealedCredentialEnvelope,
) -> Result<(), CliError> {
    let handoff = handoff.into_transport_bytes();
    let consume = CredentialServiceProtocolCodec::decode_authenticated_writer_broker_handoff(
        &handoff,
        authorization,
        effects,
        channel,
        binding,
        pending,
        envelope,
    )
    .map_err(|_| CliError::CredentialOperation)?;
    consume_request(port, CredentialServiceRequest::WriterConsume(consume))
}

pub(super) fn consume_service_control(
    effects: &CredentialWriterEffectAuthority,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    let port = runne_macos_xpc::CredentialServiceWriterXpcClient::connect(configuration)
        .map_err(|_| CliError::CredentialOperation)?;
    consume_service_control_with_port(
        &port,
        effects,
        handoff,
        authorization,
        channel,
        binding,
    )
}

pub fn consume_service_control_with_port(
    port: &impl CredentialServiceWriterPort,
    effects: &CredentialWriterEffectAuthority,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    let handoff = handoff.into_transport_bytes();
    let consume = CredentialServiceProtocolCodec::decode_authenticated_writer_control_handoff(
        &handoff,
        authorization,
        effects,
        channel,
        binding,
    )
    .map_err(|_| CliError::CredentialOperation)?;
    consume_request(port, CredentialServiceRequest::WriterConsume(consume))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn consume_service_legacy_migration(
    effects: &CredentialWriterEffectAuthority,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    legacy: &dyn BrokeredProviderCredentialLegacySource,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    let port = runne_macos_xpc::CredentialServiceWriterXpcClient::connect(configuration)
        .map_err(|_| CliError::CredentialOperation)?;
    consume_service_legacy_migration_with_port(
        &port,
        effects,
        legacy,
        handoff,
        authorization,
        channel,
        binding,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn consume_service_legacy_migration_with_port(
    port: &impl CredentialServiceWriterPort,
    effects: &CredentialWriterEffectAuthority,
    legacy: &dyn BrokeredProviderCredentialLegacySource,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    let handoff = handoff.into_transport_bytes();
    let consume = CredentialServiceProtocolCodec::decode_authenticated_writer_legacy_handoff(
        &handoff,
        authorization,
        effects,
        channel,
        binding,
        |read| {
            legacy
                .load_exact(read)
                .map_err(|_| runne_provider::CredentialEnrollmentError::InvalidEvidence)
        },
    )
    .map_err(|_| CliError::CredentialOperation)?;
    consume_request(port, CredentialServiceRequest::WriterConsume(consume))
}

fn consume_request(
    port: &impl CredentialServiceWriterPort,
    request: CredentialServiceRequest,
) -> Result<(), CliError> {
    let reply_context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request)
        .map_err(|_| CliError::CredentialOperation)?;
    let transport = CredentialServiceWriterRequest::from_zeroizing(frame.into_transport_bytes())
        .map_err(|_| CliError::CredentialOperation)?;
    consume_transport(port, transport, reply_context)
}

fn consume_transport(
    port: &impl CredentialServiceWriterPort,
    request: CredentialServiceWriterRequest,
    reply_context: CredentialServiceRequestContext,
) -> Result<(), CliError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or(CliError::CredentialOperation)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| CliError::CredentialOperation)?;
    let reply = runtime
        .block_on(port.consume_mutation(
            request,
            CredentialServiceCallContext::new(deadline, CredentialServiceCancellation::new()),
        ))
        .map_err(|_| CliError::CredentialOperation)?;
    match reply
        .with_bytes(|bytes| {
            CredentialServiceProtocolCodec::decode_writer_reply(bytes, reply_context)
        })
        .map_err(|_| CliError::CredentialOperation)?
    {
        CredentialServiceReply::Consumed => Ok(()),
        _ => Err(CliError::CredentialOperation),
    }
}
