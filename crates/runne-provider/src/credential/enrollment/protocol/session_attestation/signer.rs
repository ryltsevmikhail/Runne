use ring::{
    rand::{SecureRandom as _, SystemRandom},
    signature,
};
use zeroize::Zeroizing;

use super::qualified::{
    CredentialWriterQualifiedPreludeSigner, SignedCredentialWriterSessionAttestationV2,
};
use super::{
    CredentialWriterSessionAttestationClaimsV1, SignedCredentialWriterSessionAttestationV1, codec,
};
use crate::credential::enrollment::{
    CredentialBindingDigest, CredentialEnrollmentError,
    protocol::secret::DaemonCredentialSecretPublicationSigner,
};

/// Daemon-only signer state that must attest a session before publication exists.
pub struct CredentialWriterSessionAttestationSigner {
    key_pair: signature::Ed25519KeyPair,
    channel: CredentialBindingDigest,
}

impl CredentialWriterSessionAttestationSigner {
    /// Generates a fresh session-first signer bound to one nonzero channel.
    pub fn generate(channel: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        let channel = CredentialBindingDigest::from_measured(channel)?;
        let mut seed = Zeroizing::new([0; 32]);
        SystemRandom::new()
            .fill(seed.as_mut())
            .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        Ok(Self { key_pair, channel })
    }

    /// Returns only the expected public key for the authenticated handoff.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        use ring::signature::KeyPair as _;
        self.key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("key width")
    }

    /// Consumes the pre-attestation state and unlocks one exact publication signer.
    pub fn sign(
        self,
        claims: CredentialWriterSessionAttestationClaimsV1,
    ) -> Result<
        (
            SignedCredentialWriterSessionAttestationV1,
            DaemonCredentialSecretPublicationSigner,
        ),
        CredentialEnrollmentError,
    > {
        if claims.ticket.issue_ticket.channel() != self.channel {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let public_key = self.public_key();
        let mut record = SignedCredentialWriterSessionAttestationV1 {
            claims,
            channel: self.channel,
            publication_public_key: public_key,
            signature: [0; 64],
        };
        record.signature = self
            .key_pair
            .sign(&codec::signature_message(&record))
            .as_ref()
            .try_into()
            .expect("signature width");
        let publication = DaemonCredentialSecretPublicationSigner::after_attestation(
            self.key_pair,
            self.channel,
            record.claims.ticket.operation,
            record.claims.ticket.attempt,
            record.claims.ticket.claim,
        );
        Ok((record, publication))
    }

    /// Consumes the session signer into the qualification-required V2 phase.
    pub fn sign_qualified(
        self,
        claims: CredentialWriterSessionAttestationClaimsV1,
        launch_generation: u64,
        context_sha256: [u8; 32],
        ticket_sha256: [u8; 32],
    ) -> Result<
        (
            SignedCredentialWriterSessionAttestationV2,
            CredentialWriterQualifiedPreludeSigner,
        ),
        CredentialEnrollmentError,
    > {
        if claims.ticket.issue_ticket.channel() != self.channel
            || launch_generation == 0
            || context_sha256 == [0; 32]
            || ticket_sha256 == [0; 32]
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let public_key = self.public_key();
        let context_sha256 = CredentialBindingDigest::from_measured(context_sha256)?;
        let ticket_sha256 = CredentialBindingDigest::from_measured(ticket_sha256)?;
        let mut record = SignedCredentialWriterSessionAttestationV2 {
            claims,
            channel: self.channel,
            publication_public_key: public_key,
            launch_generation,
            context_sha256,
            ticket_sha256,
            signature: [0; 64],
        };
        record.signature = self
            .key_pair
            .sign(&super::qualified::signature_message(&record))
            .as_ref()
            .try_into()
            .expect("signature width");
        let pending =
            CredentialWriterQualifiedPreludeSigner::new(self.key_pair, self.channel, &record);
        Ok((record, pending))
    }
}
