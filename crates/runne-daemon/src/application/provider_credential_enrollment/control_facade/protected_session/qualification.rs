use super::DaemonProtectedCredentialEnrollmentSession;
use crate::protected_activation::control_v3::initial_exchange::VerifiedQualificationAdmission;
use runne_api::ProviderCredentialEnrollmentHostError;

#[cfg(test)]
mod tests;

impl DaemonProtectedCredentialEnrollmentSession {
    /// Moves the initially verified pair into a fresh session exactly once.
    /// No failure path can remove this carrier and resume ordinary issuance.
    pub(crate) fn retain_qualification(
        mut self,
        qualification: VerifiedQualificationAdmission,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        if self.qualification.is_some()
            || self.pending.is_some()
            || self.begun.is_some()
            || self.recovery.started
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.qualification = Some(qualification);
        Ok(self)
    }
}
