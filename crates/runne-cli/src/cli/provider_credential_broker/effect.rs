//! Native/service effect dispatch after an accepted writer claim.

#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use runne_provider::{CredentialBrokerFrame, CredentialOperationAction};
#[cfg(target_os = "macos")]
use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
    CredentialServiceRequestContext, CredentialWriterBrokerHandoffFrame,
    CredentialWriterEffectAuthority, PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
#[cfg(target_os = "macos")]
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation, CredentialServiceWriterPort,
    CredentialServiceWriterRequest,
};
use runne_secure_store::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, NativeProviderCredentialEffectRoute,
};

use super::{
    CliError,
    claim::{AuthorizedWriterControl, NonPairWriterEffectKind},
    pair::AuthorizedPairWriterControl,
};

/// Executes a sealed Pair effect only after source decoding and claim acceptance.
pub fn execute_pair_effect(authority: AuthorizedPairWriterControl) -> Result<(), CliError> {
    let super::pair::PairEffectParts {
        mut control,
        effect_route,
        authorization,
        command,
        binding,
        channel,
        pending,
        envelope,
        service_handoff,
    } = authority.into_effect_parts();
    if command.action() != CredentialOperationAction::Pair {
        return Err(CliError::CredentialOperation);
    }
    let result = match effect_route {
        NativeProviderCredentialEffectRoute::Legacy(writer) => {
            let input = BrokeredCreateInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .create_sealed_exact(authorization, input, pending, envelope)
                .map_err(|_| CliError::CredentialOperation)
        }
        #[cfg(target_os = "macos")]
        NativeProviderCredentialEffectRoute::CredentialService {
            effects,
            configuration,
        } => consume_service_pair(
            effects,
            configuration,
            service_handoff.ok_or(CliError::CredentialOperation)?,
            authorization,
            &channel,
            binding,
            pending,
            envelope,
        ),
    };
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
}

/// Executes a closed non-Pair effect only after native endpoint admission.
pub fn execute_non_pair_effect(authority: AuthorizedWriterControl) -> Result<(), CliError> {
    let super::claim::NonPairEffectParts {
        mut control,
        effect_route,
        authorization,
        command,
        binding,
        channel,
        effect_kind,
        service_handoff,
    } = authority.into_effect_parts();
    let result = match (effect_route, effect_kind) {
        (NativeProviderCredentialEffectRoute::Legacy(writer), effect_kind) => match effect_kind {
        NonPairWriterEffectKind::Delete => {
            let input = BrokeredDeleteInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .delete_exact(authorization, input)
                .map(|_| ())
                .map_err(|_| CliError::CredentialOperation)
        }
        NonPairWriterEffectKind::ImportLegacy => {
            let input = BrokeredMigrateLegacyInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .import_legacy_exact(authorization, input)
                .map_err(|_| CliError::CredentialOperation)
        }
        NonPairWriterEffectKind::DeleteLegacySource => {
            let input = BrokeredLegacySourceDeleteInput::new(command.clone(), binding, channel)
                .map_err(|_| CliError::CredentialOperation)?;
            writer
                .delete_legacy_source_exact(authorization, input)
                .map_err(|_| CliError::CredentialOperation)
        }
        },
        #[cfg(target_os = "macos")]
        (
            NativeProviderCredentialEffectRoute::CredentialService {
                effects,
                configuration,
            },
            NonPairWriterEffectKind::Delete,
        ) => consume_service_control(
            effects,
            configuration,
            service_handoff.ok_or(CliError::CredentialOperation)?,
            authorization,
            &channel,
            binding,
        ),
        #[cfg(target_os = "macos")]
        (NativeProviderCredentialEffectRoute::CredentialService { .. }, _) => {
            Err(CliError::CredentialOperation)
        }
    };
    control.write_frame(CredentialBrokerFrame::NativeEffectObserved {
        operation_id: command.operation_id(),
        binding,
    })?;
    result
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn consume_service_pair(
    effects: CredentialWriterEffectAuthority,
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
    let result = consume_service_pair_with_port(
        &port,
        &effects,
        handoff,
        authorization,
        channel,
        binding,
        pending,
        envelope,
    );
    drop(effects);
    result
}

#[cfg(target_os = "macos")]
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
    let request = CredentialServiceRequest::WriterConsume(consume);
    let reply_context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request)
        .map_err(|_| CliError::CredentialOperation)?;
    let transport = CredentialServiceWriterRequest::from_zeroizing(frame.into_transport_bytes())
        .map_err(|_| CliError::CredentialOperation)?;
    consume_service_request(port, transport, reply_context)
}

#[cfg(target_os = "macos")]
fn consume_service_request(
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

#[cfg(target_os = "macos")]
fn consume_service_control(
    effects: CredentialWriterEffectAuthority,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
    handoff: CredentialWriterBrokerHandoffFrame,
    authorization: ClaimedWriterAuthorization,
    channel: &BrokerChannelBinding,
    binding: CredentialBindingDigest,
) -> Result<(), CliError> {
    let port = runne_macos_xpc::CredentialServiceWriterXpcClient::connect(configuration)
        .map_err(|_| CliError::CredentialOperation)?;
    let result = consume_service_control_with_port(
        &port,
        &effects,
        handoff,
        authorization,
        channel,
        binding,
    );
    drop(effects);
    result
}

#[cfg(target_os = "macos")]
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
    let request = CredentialServiceRequest::WriterConsume(consume);
    let reply_context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request)
        .map_err(|_| CliError::CredentialOperation)?;
    let transport = CredentialServiceWriterRequest::from_zeroizing(frame.into_transport_bytes())
        .map_err(|_| CliError::CredentialOperation)?;
    consume_service_request(port, transport, reply_context)
}
