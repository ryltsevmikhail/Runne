use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
use zeroize::Zeroizing;

use super::{ClaimedBrokerEffect, CredentialBrokerChannel, ProviderCredentialBroker};

impl ProviderCredentialBroker {
    pub(crate) fn release_claimed_effect_to_channel<C: CredentialBrokerChannel>(
        &self,
        claimed: &ClaimedBrokerEffect,
        channel: &mut C,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let frame = CredentialBrokerFrame::NativeEffectRelease {
            operation_id: claimed.operation_id,
            attempt: claimed.attempt,
            binding: claimed.binding,
        };
        channel.send(Zeroizing::new(
            CredentialBrokerFrameCodec::encode(frame)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
        ))
    }
}
