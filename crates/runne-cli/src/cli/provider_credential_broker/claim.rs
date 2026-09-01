//! Writer-side claim gate for an already authenticated daemon control endpoint.

use std::{
    io::{Read, Write},
    sync::Arc,
};

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretInputPresence, CredentialWriterClaimIssuer, CredentialWriterCommandKindV1,
    CredentialWriterCommandScopeV1, PendingCredentialIssueTicketV1, PendingCredentialSecretOpening,
};
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

/// Move-only claim acknowledgement retaining the exact live control endpoint.
pub struct ClaimedWriterControl {
    control: Box<dyn BrokerControl>,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
    authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
    command_kind: CredentialWriterCommandKindV1,
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

pub enum NonPairWriterEffectKind {
    Delete,
    ImportLegacy,
    DeleteLegacySource,
}

pub struct NonPairEffectParts {
    pub control: Box<dyn BrokerControl>,
    pub writer: Arc<dyn BrokeredProviderCredentialWriter>,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub effect_kind: NonPairWriterEffectKind,
}

/// Effect authority retaining the same channel for the later exact diagnostic.
pub struct AuthorizedWriterControl {
    _control: Box<dyn BrokerControl>,
    _writer: Arc<dyn BrokeredProviderCredentialWriter>,
    _authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    _binding: CredentialBindingDigest,
    _channel: BrokerChannelBinding,
    effect_kind: NonPairWriterEffectKind,
}

impl AuthorizedWriterControl {
    pub(super) fn into_effect_parts(self) -> NonPairEffectParts {
        let Self {
            _control: control,
            _writer: writer,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
            effect_kind,
        } = self;
        NonPairEffectParts {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            effect_kind,
        }
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
            command_kind: _,
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
            command_kind,
            pending_pair_secret_opening,
        } = self;
        if pending_pair_secret_opening.is_some() {
            return Err(CliError::CredentialOperation);
        }
        let effect_kind = match command_kind {
            CredentialWriterCommandKindV1::Revoke
            | CredentialWriterCommandKindV1::RetiredVersionCleanup => {
                NonPairWriterEffectKind::Delete
            }
            CredentialWriterCommandKindV1::MigrateLegacy => {
                NonPairWriterEffectKind::ImportLegacy
            }
            CredentialWriterCommandKindV1::LegacySourceCleanup => {
                NonPairWriterEffectKind::DeleteLegacySource
            }
            CredentialWriterCommandKindV1::Pair => return Err(CliError::CredentialOperation),
        };
        Ok(AuthorizedWriterControl {
            _control: control,
            _writer: writer,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
            effect_kind,
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
pub fn claim_writer_authorization(
    writers: NativeProviderCredentialWriters,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    let (control, channel, ticket, issuer, writer) = writers
        .into_authenticated_parts()
        .map_err(|_| CliError::CredentialOperation)?;
    claim_writer_authorization_with_parts(
        control,
        channel,
        ticket,
        &issuer,
        writer,
        secret_input,
    )
}

#[cfg(any(test, target_os = "macos"))]
pub fn claim_writer_authorization_with_parts<C: Read + Write + 'static>(
    mut control: C,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    let (authorization, command, binding, command_kind, pending_pair_secret_opening) = ticket
        .claim_on(
            &mut control,
            issuer,
            &channel,
            secret_input,
            CredentialWriterCommandScopeV1::D1_1A,
        )
        .map_err(|_| CliError::CredentialOperation)?;
    Ok(ClaimedWriterControl {
        control: Box::new(control),
        writer,
        authorization,
        command,
        binding,
        channel,
        command_kind,
        pending_pair_secret_opening,
    })
}
