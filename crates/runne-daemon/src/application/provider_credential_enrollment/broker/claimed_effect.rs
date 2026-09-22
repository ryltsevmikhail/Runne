#![cfg_attr(
    not(any(
        test,
        all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        )
    )),
    expect(
        dead_code,
        reason = "the D1 Linux composition slice mounts the claim/ACK effect path; the macOS flow and tests drive it today"
    )
)]

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialBindingDigest, CredentialOperationId, CredentialSecretClaimOffer,
    CredentialSecretPublication,
};

/// Move-only authority for the one post-claim possible-effect diagnostic.
#[must_use = "the writer effect diagnostic must be consumed or reconciled after a claim"]
pub(in crate::application::provider_credential_enrollment) struct ClaimedBrokerEffect {
    pub(super) operation_id: CredentialOperationId,
    pub(super) attempt: runne_provider::CredentialTicketAttempt,
    pub(super) binding: CredentialBindingDigest,
    pub(super) publication: Option<CredentialSecretPublication>,
    pub(super) offer: Option<[u8; runne_provider::CredentialSecretOfferCodec::BYTES]>,
    pub(super) publication_taken: bool,
}

impl ClaimedBrokerEffect {
    #[cfg(all(
        feature = "desktop-protected",
        any(test, all(target_os = "macos", target_arch = "aarch64"))
    ))]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }

    #[cfg(test)]
    pub(in crate::application::provider_credential_enrollment) fn take_secret_publication(
        &mut self,
    ) -> Result<Option<CredentialSecretPublication>, ProviderCredentialEnrollmentHostError> {
        if self.publication_taken {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.publication_taken = true;
        Ok(self.publication.take())
    }

    pub(in crate::application::provider_credential_enrollment) fn take_secret_relay(
        &mut self,
    ) -> Result<
        Option<[u8; runne_provider::CredentialSecretRelayFrameCodec::BYTES]>,
        ProviderCredentialEnrollmentHostError,
    > {
        if self.publication_taken {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.publication_taken = true;
        match (self.offer.take(), self.publication.take()) {
            (Some(offer), Some(publication)) => {
                let offer = runne_provider::CredentialSecretOfferCodec::decode(&offer)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
                Ok(Some(
                    runne_provider::CredentialSecretRelayFrameCodec::encode(&offer, &publication),
                ))
            }
            (None, None) => Ok(None),
            _ => Err(ProviderCredentialEnrollmentHostError::InvariantViolation),
        }
    }
}

pub(in crate::application::provider_credential_enrollment) struct AcceptedBrokerClaim {
    pub(super) acknowledgement: Vec<u8>,
    pub(super) pending_publication: Option<CredentialSecretClaimOffer>,
}

impl AcceptedBrokerClaim {
    #[cfg(test)]
    pub(in crate::application::provider_credential_enrollment) fn acknowledgement(&self) -> &[u8] {
        &self.acknowledgement
    }
}
