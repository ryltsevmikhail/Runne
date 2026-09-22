//! Writer-side claim gate for an already authenticated daemon control endpoint.
use super::CliError;
use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialSecretInputPresence, CredentialWriterBrokerHandoffFrame, CredentialWriterClaimIssuer,
    CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1, PendingCredentialIssueTicketV1,
    PendingCredentialSecretOpening,
};
#[cfg(test)]
use runne_secure_store::BrokeredProviderCredentialWriter;
use runne_secure_store::NativeProviderCredentialEffectRoute;
#[cfg(any(test, unix))]
use runne_secure_store::NativeProviderCredentialWriters;
use std::io::{Read, Write};
#[cfg(test)]
use std::sync::Arc;
#[path = "claim/flow.rs"]
mod flow;
#[path = "qualified_deadline.rs"]
#[cfg(any(test, unix))]
mod qualified_deadline;

pub trait BrokerControl: Read + Write {
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
    effect_route: NativeProviderCredentialEffectRoute,
    authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
    command_kind: CredentialWriterCommandKindV1,
    pending_pair_secret_opening: Option<PendingCredentialSecretOpening>,
    service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

pub struct ClaimedPairParts {
    pub control: Box<dyn BrokerControl>,
    pub effect_route: NativeProviderCredentialEffectRoute,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub pending_opening: Option<PendingCredentialSecretOpening>,
    pub service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

pub enum NonPairWriterEffectKind {
    Delete,
    ImportLegacy,
    DeleteLegacySource,
}

pub struct NonPairEffectParts {
    pub control: Box<dyn BrokerControl>,
    pub effect_route: NativeProviderCredentialEffectRoute,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub effect_kind: NonPairWriterEffectKind,
    pub service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

/// Effect authority retaining the same channel for the later exact diagnostic.
pub struct AuthorizedWriterControl {
    _control: Box<dyn BrokerControl>,
    _effect_route: NativeProviderCredentialEffectRoute,
    _authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    _binding: CredentialBindingDigest,
    _channel: BrokerChannelBinding,
    effect_kind: NonPairWriterEffectKind,
    service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

impl AuthorizedWriterControl {
    pub(super) fn into_effect_parts(self) -> NonPairEffectParts {
        let Self {
            _control: control,
            _effect_route: effect_route,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
            effect_kind,
            service_handoff,
        } = self;
        NonPairEffectParts {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            effect_kind,
            service_handoff,
        }
    }
}

impl ClaimedWriterControl {
    pub(super) fn into_pair_parts(self) -> ClaimedPairParts {
        let Self {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            command_kind: _,
            pending_pair_secret_opening,
            service_handoff,
        } = self;
        ClaimedPairParts {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            pending_opening: pending_pair_secret_opening,
            service_handoff,
        }
    }

    /// Authorizes a non-Pair effect without opening or reading a secret source.
    pub fn authorize_without_secret(self) -> Result<AuthorizedWriterControl, CliError> {
        let Self {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            command_kind,
            pending_pair_secret_opening,
            service_handoff,
        } = self;
        if pending_pair_secret_opening.is_some() {
            return Err(CliError::CredentialOperation);
        }
        let effect_kind = match command_kind {
            CredentialWriterCommandKindV1::Revoke
            | CredentialWriterCommandKindV1::RetiredVersionCleanup => {
                NonPairWriterEffectKind::Delete
            }
            CredentialWriterCommandKindV1::MigrateLegacy => NonPairWriterEffectKind::ImportLegacy,
            CredentialWriterCommandKindV1::LegacySourceCleanup => {
                NonPairWriterEffectKind::DeleteLegacySource
            }
            CredentialWriterCommandKindV1::Pair => return Err(CliError::CredentialOperation),
        };
        Ok(AuthorizedWriterControl {
            _control: control,
            _effect_route: effect_route,
            _authorization: authorization,
            command,
            _binding: binding,
            _channel: channel,
            effect_kind,
            service_handoff,
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn claim_writer_authorization(
    writers: NativeProviderCredentialWriters,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    let (control, channel, ticket, issuer, effect_route) = writers
        .into_authenticated_parts()
        .map_err(|_| CliError::CredentialOperation)?;
    flow::claim_socket(
        control,
        channel,
        ticket,
        &issuer,
        effect_route,
        secret_input,
    )
}

#[cfg(test)]
pub fn claim_writer_authorization_with_legacy_parts<C: Read + Write + 'static>(
    control: C,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    flow::claim_generic(
        control,
        channel,
        ticket,
        issuer,
        NativeProviderCredentialEffectRoute::Legacy(writer),
        secret_input,
    )
}

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
pub fn claim_writer_authorization_with_service_parts<C: Read + Write + 'static>(
    control: C,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    effects: runne_provider::CredentialWriterEffectAuthority,
    legacy: Arc<dyn runne_secure_store::BrokeredProviderCredentialLegacySource>,
    secret_input: CredentialSecretInputPresence,
    configuration: runne_macos_xpc::CredentialServiceEndpointConfiguration,
) -> Result<ClaimedWriterControl, CliError> {
    let effect_route = NativeProviderCredentialEffectRoute::CredentialService {
        effects,
        configuration,
        legacy,
    };
    flow::claim_generic(control, channel, ticket, issuer, effect_route, secret_input)
}
