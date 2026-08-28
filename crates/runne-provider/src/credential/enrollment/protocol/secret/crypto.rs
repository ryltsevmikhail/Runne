use core::fmt;

use ring::{agreement, rand::SystemRandom};

use crate::credential::enrollment::authority::writer::AuthorizedCredentialSecretOpening;
use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerTarget,
    CredentialEnrollmentError, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};

/// One writer-bound offer for a credential relay that has not been accepted.
pub struct CredentialSecretClaimOffer {
    pub(crate) operation_id: CredentialOperationId,
    pub(crate) attempt: CredentialTicketAttempt,
    pub(crate) claim_binding: CredentialBindingDigest,
    pub(crate) writer_public_key: [u8; 32],
    pub(crate) offer_binding: CredentialBindingDigest,
}

/// Move-only writer private state for exactly one accepted credential relay.
pub struct PendingCredentialSecretOpening {
    command: CredentialBrokerCommand,
    operation_id: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim_binding: CredentialBindingDigest,
    writer_public_key: [u8; 32],
    offer_binding: CredentialBindingDigest,
    writer_private_key: agreement::EphemeralPrivateKey,
}

/// Encrypted credential relay bound to one accepted writer transcript.
pub struct SealedCredentialEnvelope {
    pub(crate) operation_id: CredentialOperationId,
    pub(crate) attempt: CredentialTicketAttempt,
    pub(crate) claim_binding: CredentialBindingDigest,
    pub(crate) offer_binding: CredentialBindingDigest,
    pub(crate) sealer_public_key: [u8; 32],
    pub(crate) plaintext_len: u16,
    pub(crate) ciphertext_and_tag: zeroize::Zeroizing<Vec<u8>>,
}

/// Decrypted credential material for the immediately following native writer effect.
pub(crate) struct CredentialDecryptedMaterial {
    material: zeroize::Zeroizing<Vec<u8>>,
}

/// Exact native command plus decrypted material after effect admission and AEAD open.
pub(crate) struct OpenedCredentialSecretEffect {
    command: CredentialBrokerCommand,
    material: CredentialDecryptedMaterial,
}

impl CredentialSecretClaimOffer {
    /// Generates a writer X25519 offer bound to one command and claim digest.
    pub fn prepare(
        command: &CredentialBrokerCommand,
        claim_binding: CredentialBindingDigest,
    ) -> Result<(Self, PendingCredentialSecretOpening), CredentialEnrollmentError> {
        if command.action() != CredentialOperationAction::Pair
            || !matches!(command.target(), CredentialBrokerTarget::Version(_))
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
                .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        let writer_public_key = public_key(&private)?;
        let offer_binding = super::cipher::offer_binding(
            command.operation_id(),
            command.ticket_attempt(),
            claim_binding,
            writer_public_key,
        );
        Ok((
            Self {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
                claim_binding,
                writer_public_key,
                offer_binding,
            },
            PendingCredentialSecretOpening {
                command: command.clone(),
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
                claim_binding,
                writer_public_key,
                offer_binding,
                writer_private_key: private,
            },
        ))
    }

    pub(crate) fn from_decoded(
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim_binding: CredentialBindingDigest,
        writer_public_key: [u8; 32],
        decoded_offer_binding: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        if decoded_offer_binding
            != super::cipher::offer_binding(operation_id, attempt, claim_binding, writer_public_key)
        {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        Ok(Self {
            operation_id,
            attempt,
            claim_binding,
            writer_public_key,
            offer_binding: decoded_offer_binding,
        })
    }
}

impl super::publication::VerifiedCredentialSecretOffer {
    /// Encrypts one nonempty, single-line credential for the matching writer.
    pub(crate) fn seal(
        self,
        credential: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<SealedCredentialEnvelope, CredentialEnrollmentError> {
        super::cipher::validate_credential(&credential)?;
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
                .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        let sealer_public_key = public_key(&private)?;
        let peer =
            agreement::UnparsedPublicKey::new(&agreement::X25519, self.offer.writer_public_key);
        agreement::agree_ephemeral(private, &peer, |shared| {
            self.seal_shared(shared, sealer_public_key, credential)
        })
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)?
    }

    fn seal_shared(
        &self,
        shared: &[u8],
        sealer_public_key: [u8; 32],
        credential: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<SealedCredentialEnvelope, CredentialEnrollmentError> {
        let plaintext_len =
            u16::try_from(credential.len()).map_err(|_| CredentialEnrollmentError::InvalidInput)?;
        let transcript = super::cipher::CipherTranscript {
            operation: self.offer.operation_id,
            attempt: self.offer.attempt,
            claim: self.offer.claim_binding,
            offer: self.offer.offer_binding,
            writer: self.offer.writer_public_key,
            sealer: sealer_public_key,
            length: plaintext_len,
        };
        let ciphertext_and_tag = super::cipher::seal(shared, &transcript, credential)?;
        Ok(SealedCredentialEnvelope {
            operation_id: self.offer.operation_id,
            attempt: self.offer.attempt,
            claim_binding: self.offer.claim_binding,
            offer_binding: self.offer.offer_binding,
            sealer_public_key,
            plaintext_len,
            ciphertext_and_tag,
        })
    }
}

impl PendingCredentialSecretOpening {
    /// Consumes pending state, authorization, and envelope to open one exact relay.
    pub(crate) fn open_after_claim(
        self,
        authorization: AuthorizedCredentialSecretOpening,
        channel: &BrokerChannelBinding,
        envelope: SealedCredentialEnvelope,
    ) -> Result<OpenedCredentialSecretEffect, CredentialEnrollmentError> {
        let Self {
            command,
            operation_id,
            attempt,
            claim_binding,
            writer_public_key,
            offer_binding,
            writer_private_key,
        } = self;
        if !authorization.matches(&command, claim_binding, channel.digest()) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let SealedCredentialEnvelope {
            operation_id: received_operation,
            attempt: received_attempt,
            claim_binding: received_claim,
            offer_binding: received_offer,
            sealer_public_key,
            plaintext_len,
            ciphertext_and_tag,
        } = envelope;
        if received_operation != operation_id
            || received_attempt != attempt
            || received_claim != claim_binding
            || received_offer != offer_binding
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, sealer_public_key);
        let transcript = super::cipher::CipherTranscript {
            operation: operation_id,
            attempt,
            claim: claim_binding,
            offer: offer_binding,
            writer: writer_public_key,
            sealer: sealer_public_key,
            length: plaintext_len,
        };
        let material = agreement::agree_ephemeral(writer_private_key, &peer, |shared| {
            super::cipher::open(shared, &transcript, ciphertext_and_tag)
        })
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)??;
        super::cipher::validate_credential(&material)?;
        Ok(OpenedCredentialSecretEffect {
            command,
            material: CredentialDecryptedMaterial { material },
        })
    }
}

#[cfg(test)]
impl CredentialDecryptedMaterial {
    pub(super) fn test_bytes(&self) -> &[u8] {
        &self.material
    }
}

#[cfg(test)]
impl OpenedCredentialSecretEffect {
    pub(super) fn test_command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    pub(super) fn test_material(&self) -> &CredentialDecryptedMaterial {
        &self.material
    }
}

impl SealedCredentialEnvelope {
    pub(crate) fn from_decoded(
        operation_id: CredentialOperationId,
        attempt: CredentialTicketAttempt,
        claim_binding: CredentialBindingDigest,
        offer_binding: CredentialBindingDigest,
        sealer_public_key: [u8; 32],
        plaintext_len: u16,
        ciphertext_and_tag: zeroize::Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            operation_id,
            attempt,
            claim_binding,
            offer_binding,
            sealer_public_key,
            plaintext_len,
            ciphertext_and_tag,
        }
    }
}

fn public_key(
    private: &agreement::EphemeralPrivateKey,
) -> Result<[u8; 32], CredentialEnrollmentError> {
    private
        .compute_public_key()
        .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?
        .as_ref()
        .try_into()
        .map_err(|_| CredentialEnrollmentError::InvalidEvidence)
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(concat!(stringify!($type), "(<redacted>)"))
                }
            }
        )+
    };
}
redacted_debug!(
    CredentialSecretClaimOffer,
    PendingCredentialSecretOpening,
    SealedCredentialEnvelope,
    CredentialDecryptedMaterial,
    OpenedCredentialSecretEffect
);
