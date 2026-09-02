//! Sealed Pair relay state retained after an exact claim acknowledgement.

use std::{
    io::Read,
    sync::Arc,
};

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialOperationAction,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
};
use runne_secure_store::BrokeredProviderCredentialWriter;

use super::{
    CliError,
    claim::{BrokerControl, ClaimedWriterControl},
    secret::read_sealed_pair_envelope,
};

/// Move-only Pair authority retaining only sealed secret relay state.
pub struct AuthorizedPairWriterControl {
    control: Box<dyn BrokerControl>,
    writer: Arc<dyn BrokeredProviderCredentialWriter>,
    authorization: ClaimedWriterAuthorization,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: BrokerChannelBinding,
    pending_opening: PendingCredentialSecretOpening,
    envelope: SealedCredentialEnvelope,
}

pub struct PairEffectParts {
    pub control: Box<dyn BrokerControl>,
    pub writer: Arc<dyn BrokeredProviderCredentialWriter>,
    pub authorization: ClaimedWriterAuthorization,
    pub command: CredentialBrokerCommand,
    pub binding: CredentialBindingDigest,
    pub channel: BrokerChannelBinding,
    pub pending: PendingCredentialSecretOpening,
    pub envelope: SealedCredentialEnvelope,
}

impl ClaimedWriterControl {
    /// Reads and decodes one sealed Pair envelope after exact claim acceptance.
    pub fn read_pair_secret(
        self,
        reader: &mut impl Read,
    ) -> Result<AuthorizedPairWriterControl, CliError> {
        let super::claim::ClaimedPairParts {
            mut control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
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
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
            envelope,
        })
    }
}

impl AuthorizedPairWriterControl {
    pub(super) fn into_effect_parts(self) -> PairEffectParts {
        let Self {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending_opening,
            envelope,
        } = self;
        PairEffectParts {
            control,
            writer,
            authorization,
            command,
            binding,
            channel,
            pending: pending_opening,
            envelope,
        }
    }
}
