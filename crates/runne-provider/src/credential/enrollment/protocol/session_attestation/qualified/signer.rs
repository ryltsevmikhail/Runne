use ring::signature;

use super::{
    CredentialWriterQualifiedAckV1, CredentialWriterQualifiedPreludeCodec,
    CredentialWriterQualifiedPreludeV1, SignedCredentialWriterSessionAttestationV2,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt, protocol::secret::DaemonCredentialSecretPublicationSigner,
};

/// Consuming signer state between V2 attestation and the exact prelude ACK.
pub struct CredentialWriterQualifiedPreludeSigner {
    key_pair: signature::Ed25519KeyPair,
    channel: CredentialBindingDigest,
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    attestation_digest: [u8; 32],
}

impl CredentialWriterQualifiedPreludeSigner {
    pub(crate) fn new(
        key_pair: signature::Ed25519KeyPair,
        channel: CredentialBindingDigest,
        record: &SignedCredentialWriterSessionAttestationV2,
    ) -> Self {
        Self {
            key_pair,
            channel,
            operation: record.claims.ticket.operation,
            attempt: record.claims.ticket.attempt,
            claim: record.claims.ticket.claim,
            attestation_digest: record.full_digest(),
        }
    }

    /// Signs one bounded canonical admission bundle and waits for its ACK.
    pub fn sign_prelude(
        self,
        bundle: Vec<u8>,
    ) -> Result<
        (
            CredentialWriterQualifiedPreludeV1,
            CredentialWriterQualifiedAckSigner,
        ),
        CredentialEnrollmentError,
    > {
        let prelude = CredentialWriterQualifiedPreludeCodec::sign(
            &self.key_pair,
            self.attestation_digest,
            bundle,
        )?;
        let prelude_digest = prelude.full_digest();
        Ok((
            prelude,
            CredentialWriterQualifiedAckSigner {
                key_pair: self.key_pair,
                channel: self.channel,
                operation: self.operation,
                attempt: self.attempt,
                claim: self.claim,
                attestation_digest: self.attestation_digest,
                prelude_digest,
            },
        ))
    }
}

/// Consuming signer state that unlocks publication only after the exact ACK.
pub struct CredentialWriterQualifiedAckSigner {
    key_pair: signature::Ed25519KeyPair,
    channel: CredentialBindingDigest,
    operation: CredentialOperationId,
    attempt: CredentialTicketAttempt,
    claim: CredentialBindingDigest,
    attestation_digest: [u8; 32],
    prelude_digest: [u8; 32],
}

impl CredentialWriterQualifiedAckSigner {
    /// Builds the only ACK accepted by this one-shot pending state.
    #[must_use]
    pub fn expected_ack(
        &self,
        _prelude: &CredentialWriterQualifiedPreludeV1,
    ) -> CredentialWriterQualifiedAckV1 {
        CredentialWriterQualifiedAckV1::new(self.attestation_digest, self.prelude_digest)
    }

    /// Consumes the exact ACK and unlocks the existing publication signer.
    pub fn accept_ack(
        self,
        ack: CredentialWriterQualifiedAckV1,
    ) -> Result<DaemonCredentialSecretPublicationSigner, CredentialEnrollmentError> {
        if ack.attestation_digest != self.attestation_digest
            || ack.prelude_digest != self.prelude_digest
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(DaemonCredentialSecretPublicationSigner::after_attestation(
            self.key_pair,
            self.channel,
            self.operation,
            self.attempt,
            self.claim,
        ))
    }
}
