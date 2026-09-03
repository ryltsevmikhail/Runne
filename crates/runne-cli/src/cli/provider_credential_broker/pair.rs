//! Sealed Pair relay state retained after an exact claim acknowledgement.

use std::io::Read;

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialOperationAction,
    CredentialWriterBrokerHandoffFrame, PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
use runne_secure_store::NativeProviderCredentialEffectRoute;

use super::{
    CliError,
    claim::{BrokerControl, ClaimedWriterControl},
    secret::read_sealed_pair_envelope,
};

/// Move-only Pair authority retaining only sealed secret relay state.
pub struct AuthorizedPairWriterControl {
    control: Box<dyn BrokerControl>,
    effect_route: NativeProviderCredentialEffectRoute,
    authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
    pending_opening: PendingCredentialSecretOpening,
    envelope: SealedCredentialEnvelope,
    service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

pub struct PairEffectParts {
    pub control: Box<dyn BrokerControl>,
    pub effect_route: NativeProviderCredentialEffectRoute,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub pending: PendingCredentialSecretOpening,
    pub envelope: SealedCredentialEnvelope,
    pub service_handoff: Option<CredentialWriterBrokerHandoffFrame>,
}

impl ClaimedWriterControl {
    /// Reads and decodes one sealed Pair envelope after exact claim acceptance.
    pub fn read_pair_secret(
        self,
        reader: &mut impl Read,
    ) -> Result<AuthorizedPairWriterControl, CliError> {
        let super::claim::ClaimedPairParts {
            mut control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
            service_handoff,
        } = self.into_pair_parts();
        let pending_opening = pending_opening.ok_or(CliError::CredentialOperation)?;
        if command.action() != CredentialOperationAction::Pair {
            return Err(CliError::CredentialOperation);
        }
        let envelope = read_sealed_pair_envelope(reader)?;
        let release = control.read_frame()?;
        if !matches!(
            release,
            CredentialBrokerFrame::NativeEffectRelease {
                operation_id,
                attempt,
                binding: released_binding,
            } if operation_id == command.operation_id()
                && attempt == command.ticket_attempt()
                && released_binding == binding
        ) {
            return Err(CliError::CredentialOperation);
        }
        #[cfg(feature = "local-native-enrollment-test")]
        if runne_secure_store::test_support::local_writer_death_after_release_enabled() {
            return Err(CliError::CredentialOperation);
        }
        Ok(AuthorizedPairWriterControl {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
            envelope,
            service_handoff,
        })
    }
}

impl AuthorizedPairWriterControl {
    pub(super) fn into_effect_parts(self) -> PairEffectParts {
        let Self {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
            envelope,
            service_handoff,
        } = self;
        PairEffectParts {
            control,
            effect_route,
            authorization,
            command,
            binding,
            channel,
            pending: pending_opening,
            envelope,
            service_handoff,
        }
    }
}
