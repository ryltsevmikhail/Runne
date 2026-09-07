use std::sync::Arc;

use crate::credential::enrollment::protocol::VerifiedWriterQualificationFault;
use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialEnrollmentError, PendingCredentialSecretOpening, SealedCredentialEnvelope,
};

#[derive(Debug)]
pub(crate) struct WriterAuthoritySeal;

/// Pair of process-local issuers for one writer-authorization domain.
pub struct CredentialWriterAuthorityPair {
    issuer: CredentialWriterClaimIssuer,
    effects: CredentialWriterEffectAuthority,
}

impl CredentialWriterAuthorityPair {
    /// Creates one isolated writer authorization domain without persistent key material.
    pub fn new() -> Self {
        let seal = Arc::new(WriterAuthoritySeal);
        Self {
            issuer: CredentialWriterClaimIssuer { seal: seal.clone() },
            effects: CredentialWriterEffectAuthority { seal },
        }
    }

    /// Separates claim admission from native-effect consumption.
    pub fn split(self) -> (CredentialWriterClaimIssuer, CredentialWriterEffectAuthority) {
        (self.issuer, self.effects)
    }
}

impl Default for CredentialWriterAuthorityPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-local issuer for one pending writer claim transcript.
pub struct CredentialWriterClaimIssuer {
    seal: Arc<WriterAuthoritySeal>,
}

/// One unaccepted claim transcript; it holds no ticket or credential bytes.
pub struct PendingCredentialWriterClaim {
    seal: Arc<WriterAuthoritySeal>,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel_binding: CredentialBindingDigest,
    qualification_fault: Option<VerifiedWriterQualificationFault>,
}

/// One process-local authority consumed by exactly one matching native effect.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// fn require_serialize<T: serde::Serialize>() {}
/// require_clone::<runne_provider::ClaimedWriterAuthorization>();
/// require_serialize::<runne_provider::ClaimedWriterAuthorization>();
/// ```
/// ```compile_fail
/// use runne_provider::{ClaimedWriterAuthorization, CredentialBrokerFrame};
/// fn cannot_construct(accepted: CredentialBrokerFrame) {
///     let _ = ClaimedWriterAuthorization::new(accepted);
/// }
/// ```
pub struct ClaimedWriterAuthorization {
    seal: Arc<WriterAuthoritySeal>,
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel_binding: CredentialBindingDigest,
    #[allow(
        dead_code,
        reason = "Task 3 consumes the retained Writer fault at its exact hook"
    )]
    qualification_fault: Option<VerifiedWriterQualificationFault>,
}

#[cfg(test)]
impl ClaimedWriterAuthorization {
    pub(crate) fn test_only_has_writer_fault(&self) -> bool {
        self.qualification_fault.is_some()
    }
}

/// One effect authority admitted before a sealed credential may be opened.
#[allow(
    dead_code,
    reason = "the native Pair writer has not yet consumed the crate-private opening capability"
)]
pub(crate) struct AuthorizedCredentialSecretOpening {
    command: CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel_binding: CredentialBindingDigest,
}

/// Process-local consumer that grants exactly one matching native command.
pub struct CredentialWriterEffectAuthority {
    seal: Arc<WriterAuthoritySeal>,
}

impl CredentialWriterClaimIssuer {
    /// Captures the pending same-channel transcript before claim acknowledgement.
    pub fn issue_pending_claim(
        &self,
        command: &CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> PendingCredentialWriterClaim {
        PendingCredentialWriterClaim {
            seal: self.seal.clone(),
            command: command.clone(),
            binding,
            channel_binding: channel.digest(),
            qualification_fault: None,
        }
    }

    pub(crate) fn retain_qualification_fault(
        mut pending: PendingCredentialWriterClaim,
        fault: VerifiedWriterQualificationFault,
    ) -> PendingCredentialWriterClaim {
        pending.qualification_fault = Some(fault);
        pending
    }

    /// Converts a matching accepted broker frame and pending transcript into one authorization.
    pub fn claim_accepted(
        &self,
        pending: PendingCredentialWriterClaim,
        accepted: CredentialBrokerFrame,
        command: &CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> Result<ClaimedWriterAuthorization, CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &pending.seal)
            || pending.command != *command
            || pending.binding != binding
            || pending.channel_binding != channel.digest()
            || !matches!(accepted, CredentialBrokerFrame::ClaimAccepted { operation_id, attempt }
                if operation_id == command.operation_id() && attempt == command.ticket_attempt())
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(ClaimedWriterAuthorization {
            seal: pending.seal,
            command: pending.command,
            binding: pending.binding,
            channel_binding: pending.channel_binding,
            qualification_fault: pending.qualification_fault,
        })
    }
}

impl CredentialWriterEffectAuthority {
    pub(crate) fn legacy_read_seal(&self) -> Arc<WriterAuthoritySeal> {
        Arc::clone(&self.seal)
    }

    /// Consumes one exact Pair authority and borrows plaintext only for `callback`.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the authority boundary must receive each non-substitutable Pair capability explicitly"
    )]
    pub fn authorize_and_consume_sealed_pair<E>(
        &self,
        authorization: ClaimedWriterAuthorization,
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
        pending: PendingCredentialSecretOpening,
        envelope: SealedCredentialEnvelope,
        callback: impl FnOnce(&[u8]) -> Result<(), E>,
    ) -> Result<Result<(), E>, CredentialEnrollmentError> {
        let opening = self.authorize_secret_opening(authorization, command, binding, channel)?;
        let material = pending.open_after_claim(opening, channel, envelope)?;
        Ok(material.consume(callback))
    }

    /// Consumes exact writer authority before any credential decryption.
    #[allow(
        dead_code,
        reason = "the native Pair writer has not yet consumed the crate-private opening capability"
    )]
    pub(crate) fn authorize_secret_opening(
        &self,
        authorization: ClaimedWriterAuthorization,
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> Result<AuthorizedCredentialSecretOpening, CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &authorization.seal)
            || authorization.command != command
            || authorization.binding != binding
            || authorization.channel_binding != channel.digest()
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(AuthorizedCredentialSecretOpening {
            command,
            binding,
            channel_binding: channel.digest(),
        })
    }

    /// Consumes one authority and returns only its exact same-channel command.
    pub fn authorize(
        &self,
        authorization: ClaimedWriterAuthorization,
        command: CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: &BrokerChannelBinding,
    ) -> Result<CredentialBrokerCommand, CredentialEnrollmentError> {
        if !Arc::ptr_eq(&self.seal, &authorization.seal)
            || authorization.command != command
            || authorization.binding != binding
            || authorization.channel_binding != channel.digest()
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(command)
    }
}

impl AuthorizedCredentialSecretOpening {
    #[allow(
        dead_code,
        reason = "the native Pair writer has not yet consumed the crate-private opening capability"
    )]
    pub(crate) fn matches(
        &self,
        command: &CredentialBrokerCommand,
        binding: CredentialBindingDigest,
        channel: CredentialBindingDigest,
    ) -> bool {
        self.command == *command && self.binding == binding && self.channel_binding == channel
    }
}

impl core::fmt::Debug for AuthorizedCredentialSecretOpening {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedCredentialSecretOpening(<redacted>)")
    }
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
