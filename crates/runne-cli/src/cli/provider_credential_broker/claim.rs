//! Writer-side claim gate for an already authenticated daemon control endpoint.

use std::{
    io::{Read, Write},
    sync::Arc,
};

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    PendingCredentialSecretOpening,
};
#[cfg(test)]
use runne_provider::{CredentialOperationAction, CredentialWriterClaimIssuer};
use runne_secure_store::{
    BrokeredProviderCredentialWriter, NativeProviderCredentialWriters,
};

use super::CliError;

pub trait BrokerControl {
    fn read_frame(&mut self) -> Result<CredentialBrokerFrame, CliError>;
    fn write_frame(&mut self, frame: CredentialBrokerFrame) -> Result<(), CliError>;
}

impl<T: Read + Write> BrokerControl for T {
    fn read_frame(&mut self) -> Result<CredentialBrokerFrame, CliError> {
        CredentialBrokerFrameCodec::read_from(self).map_err(|_| CliError::CredentialOperation)
    }

    fn write_frame(&mut self, frame: CredentialBrokerFrame) -> Result<(), CliError> {
        CredentialBrokerFrameCodec::write_to(self, frame).map_err(|_| CliError::CredentialOperation)
    }
}

/// Opaque authority for one live, native-admitted daemon control endpoint.
///
/// There is deliberately no production constructor. Native admission must mint
/// it only from retained daemon peer, release tuple and channel evidence. The
/// first exact `IssueTicket` on that channel is the sole command source.
#[cfg(test)]
pub struct AuthenticatedDaemonControlEndpoint {
    control: Box<dyn BrokerControl>,
    channel_bytes: [u8; 32],
    channel: BrokerChannelBinding,
}

#[cfg(test)]
impl AuthenticatedDaemonControlEndpoint {
    pub fn for_test<T: Read + Write + 'static>(
        control: T,
        channel_bytes: [u8; 32],
        channel: BrokerChannelBinding,
    ) -> Self {
        Self {
            control: Box::new(control),
            channel_bytes,
            channel,
        }
    }
}

/// Move-only claim acknowledgement retaining the exact live control endpoint.
pub struct ClaimedWriterControl {
    control: Box<dyn BrokerControl>,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
    authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
    pending_pair_secret_opening: Option<PendingCredentialSecretOpening>,
}

pub struct ClaimedPairParts {
    pub control: Box<dyn BrokerControl>,
    pub writer: Arc<dyn BrokeredProviderCredentialWriter>,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub pending_opening: Option<PendingCredentialSecretOpening>,
}

/// Effect authority retaining the same channel for the later exact diagnostic.
pub struct AuthorizedWriterControl {
    _control: Box<dyn BrokerControl>,
    _writer: Arc<dyn BrokeredProviderCredentialWriter>,
    _authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    _binding: CredentialBindingDigest,
    _channel: BrokerChannelBinding,
}

impl AuthorizedWriterControl {
    pub(super) fn into_effect_parts(
        self,
    ) -> (
        Box<dyn BrokerControl>,
        Arc<dyn BrokeredProviderCredentialWriter>,
        ClaimedWriterAuthorization,
        CredentialBrokerCommand,
        CredentialBindingDigest,
        BrokerChannelBinding,
    ) {
        let Self {
            _control: control,
            _writer: writer,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
        } = self;
        (control, writer, authorization, command, binding, channel)
    }
}

impl ClaimedWriterControl {
    pub(super) fn into_pair_parts(self) -> ClaimedPairParts {
        let Self {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_pair_secret_opening,
        } = self;
        ClaimedPairParts {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_opening: pending_pair_secret_opening,
        }
    }

    /// Authorizes a non-Pair effect without opening or reading a secret source.
    pub fn authorize_without_secret(self) -> Result<AuthorizedWriterControl, CliError> {
        let Self {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_pair_secret_opening,
        } = self;
        if pending_pair_secret_opening.is_some() {
            return Err(CliError::CredentialOperation);
        }
        Ok(AuthorizedWriterControl {
            _control: control,
            _writer: writer,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
        })
    }
}

#[cfg(test)]
impl AuthorizedWriterControl {
    pub const fn command_for_test(&self) -> &CredentialBrokerCommand {
        &self.command
    }
}

/// Claims one exact issued ticket and returns only a matching post-ack authority.
#[cfg(target_os = "macos")]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the separate authenticated secret pipe is composed by native orchestration"
    )
)]
pub fn claim_writer_authorization(
    writers: NativeProviderCredentialWriters,
) -> Result<ClaimedWriterControl, CliError> {
    let (mut control, channel, ticket, issuer, writer) = writers
        .into_authenticated_parts()
        .map_err(|_| CliError::CredentialOperation)?;
    let (authorization, command, binding, pending_pair_secret_opening) = ticket
        .claim_on(&mut control, &issuer, &channel)
        .map_err(|_| CliError::CredentialOperation)?;
    Ok(ClaimedWriterControl {
        control: Box::new(control),
        writer,
        authorization,
        command,
        binding,
        channel,
        pending_pair_secret_opening,
    })
}

#[cfg(test)]
pub fn claim_writer_authorization_for_test(
    endpoint: AuthenticatedDaemonControlEndpoint,
    issuer: &CredentialWriterClaimIssuer,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
) -> Result<ClaimedWriterControl, CliError> {
    claim_writer_authorization_with_parts(endpoint, issuer, writer)
}

#[cfg(test)]
fn claim_writer_authorization_with_parts(
    mut endpoint: AuthenticatedDaemonControlEndpoint,
    issuer: &CredentialWriterClaimIssuer,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
) -> Result<ClaimedWriterControl, CliError> {
    if endpoint.channel.digest().as_bytes() != endpoint.channel_bytes {
        return Err(CliError::CredentialOperation);
    }
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        channel_binding,
        binding,
        command,
    } = endpoint.control.read_frame()?
    else {
        return Err(CliError::CredentialOperation);
    };
    if operation_id != command.operation_id()
        || attempt != command.ticket_attempt()
        || channel_binding != endpoint.channel_bytes
    {
        return Err(CliError::CredentialOperation);
    }

    let pending_claim = issuer.issue_pending_claim(&command, binding, &endpoint.channel);
    let (secret_offer, pending_pair_secret_opening) =
        if command.action() == CredentialOperationAction::Pair {
            let (offer, pending) =
                runne_provider::CredentialSecretClaimOffer::prepare(&command, binding)
                    .map_err(|_| CliError::CredentialOperation)?;
            (Some(offer), Some(pending))
        } else {
            (None, None)
        };
    endpoint.control.write_frame(CredentialBrokerFrame::Claim {
        operation_id,
        attempt,
        ticket,
        binding,
        secret_offer,
    })?;
    let accepted = endpoint.control.read_frame()?;
    let authorization = issuer
        .claim_accepted(
            pending_claim,
            accepted,
            &command,
            binding,
            &endpoint.channel,
        )
        .map_err(|_| CliError::CredentialOperation)?;

    Ok(ClaimedWriterControl {
        control: endpoint.control,
        writer,
        authorization,
        command,
        binding,
        channel: endpoint.channel,
        pending_pair_secret_opening,
    })
}
