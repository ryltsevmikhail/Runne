use super::{CredentialIssueTicketBindingV1, PendingCredentialIssueTicketV1};
use crate::{
    BrokerChannelBinding, CredentialEnrollmentError, CredentialLegacyReadVerifier,
    CredentialWriterEffectAuthority,
};

impl PendingCredentialIssueTicketV1 {
    /// Retains a native-consumer verifier without exposing ticket bytes.
    /// The caller must obtain this ticket and effect authority from the same
    /// authenticated session; this method is not session authentication.
    pub fn legacy_read_verifier(
        &self,
        effects: &CredentialWriterEffectAuthority,
        channel: &BrokerChannelBinding,
    ) -> Result<CredentialLegacyReadVerifier, CredentialEnrollmentError> {
        let actual = CredentialIssueTicketBindingV1::from_issue_ticket(&self.frame)?;
        if actual != self.binding || actual.channel != channel.digest() {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(effects.legacy_read_verifier(actual.claim, channel))
    }
}
