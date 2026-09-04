use std::sync::Arc;

use crate::credential::enrollment::authority::writer::WriterAuthoritySeal;
use crate::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialEnrollmentError, CredentialWriterEffectAuthority,
};

/// One native legacy-source read admitted by an authenticated writer claim.
/// Metadata getters do not reproduce this move-only capability.
///
/// ```
/// use runne_provider::{AuthorizedCredentialLegacyRead, CredentialBrokerCommand};
/// fn inspect(read: &AuthorizedCredentialLegacyRead) -> &CredentialBrokerCommand {
///     read.command()
/// }
/// ```
///
/// ```compile_fail
/// use runne_provider::AuthorizedCredentialLegacyRead;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthorizedCredentialLegacyRead>();
/// ```
///
/// ```compile_fail
/// use runne_provider::{AuthorizedCredentialLegacyRead, CredentialBindingDigest,
///     CredentialBrokerCommand, CredentialWriterEffectAuthority};
/// fn forge(command: CredentialBrokerCommand, binding: CredentialBindingDigest,
///     effects: &CredentialWriterEffectAuthority) {
///     let _ = AuthorizedCredentialLegacyRead::new(command, binding, binding, effects);
/// }
/// ```
///
/// ```compile_fail
/// use runne_provider::AuthorizedCredentialLegacyRead;
/// fn consume(_: AuthorizedCredentialLegacyRead) {}
/// fn replay(read: AuthorizedCredentialLegacyRead) {
///     consume(read);
///     consume(read);
/// }
/// ```
pub struct AuthorizedCredentialLegacyRead {
    seal: Arc<WriterAuthoritySeal>,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel_digest: CredentialBindingDigest,
}

impl AuthorizedCredentialLegacyRead {
    pub(super) fn new(
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel_digest: CredentialBindingDigest,
        effects: &CredentialWriterEffectAuthority,
    ) -> Self {
        Self {
            seal: effects.legacy_read_seal(),
            command,
            binding,
            channel_digest,
        }
    }

    #[must_use]
    /// Exact migration command authenticated by the writer claim.
    pub const fn command(&self) -> &CredentialBrokerCommand {
        &self.command
    }

    #[must_use]
    /// Binding authenticated with the consumed writer claim.
    pub const fn binding(&self) -> CredentialBindingDigest {
        self.binding
    }

    #[must_use]
    /// Exact protected channel digest authenticated with the claim.
    pub const fn channel_digest(&self) -> CredentialBindingDigest {
        self.channel_digest
    }
}

/// Verifies legacy-read provenance against a retained writer authority and session.
/// Creating another authority with identical metadata cannot reproduce its seal.
pub struct CredentialLegacyReadVerifier {
    seal: Arc<WriterAuthoritySeal>,
    binding: CredentialBindingDigest,
    channel_digest: CredentialBindingDigest,
}

impl CredentialWriterEffectAuthority {
    /// Retains the exact authority, claim binding and channel for a native consumer.
    #[must_use]
    pub fn legacy_read_verifier(
        &self,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> CredentialLegacyReadVerifier {
        CredentialLegacyReadVerifier {
            seal: self.legacy_read_seal(),
            binding,
            channel_digest: channel.digest(),
        }
    }
}

impl CredentialLegacyReadVerifier {
    /// Checks that cleanup uses the factory-retained effect authority and session.
    /// The caller must still consume an exact command authorization before native access.
    pub fn validate_effect_context(
        &self,
        effects: &CredentialWriterEffectAuthority,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> Result<(), CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &effects.legacy_read_seal())
            || self.binding != binding
            || self.channel_digest != channel.digest()
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(())
    }
    /// Rejects tokens issued by another authority or for another session binding.
    /// This check does not consume the token; the native read must take ownership.
    pub fn validate(
        &self,
        read: &AuthorizedCredentialLegacyRead,
    ) -> Result<(), CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &read.seal)
            || self.binding != read.binding
            || self.channel_digest != read.channel_digest
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(())
    }
}
