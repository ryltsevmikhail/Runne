use std::sync::Arc;

use crate::credential::enrollment::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialEnrollmentError,
};

#[derive(Debug)]
struct WriterAuthoritySeal;

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
        }
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
        })
    }
}

impl CredentialWriterEffectAuthority {
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

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
