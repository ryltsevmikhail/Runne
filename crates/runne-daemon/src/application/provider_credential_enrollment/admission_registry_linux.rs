//! Platform gate attachment, separate from one-shot admission bookkeeping.
use super::*;

impl PendingCredentialAdmissions {
    /// Attaches the Linux preadmission gate (default OFF until set).
    #[cfg(target_os = "linux")]
    #[must_use]
    pub(in crate::application::provider_credential_enrollment) fn with_linux_preadmission(
        mut self,
        gate: crate::application::provider_credential_enrollment::linux_preadmission::DaemonLinuxPreadmission,
    ) -> Self {
        self.linux_preadmission = Some(gate);
        self
    }

    #[cfg(target_os = "linux")]
    pub(in crate::application::provider_credential_enrollment) fn enforce_linux_preadmission(
        &self,
        provider: ProviderCredentialProviderV2,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        // A registry without an attached gate is outside the Linux protected
        // admission scope (unit/macOS construction); the production Linux
        // constructor always attaches a gate whose policy is default OFF.
        if let Some(gate) = &self.linux_preadmission {
            return gate.enforce(provider);
        }
        Ok(())
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(in crate::application::provider_credential_enrollment) fn set_linux_gate_for_test(
        &mut self,
        gate: crate::application::provider_credential_enrollment::linux_preadmission::DaemonLinuxPreadmission,
    ) {
        self.linux_preadmission = Some(gate);
    }
}
