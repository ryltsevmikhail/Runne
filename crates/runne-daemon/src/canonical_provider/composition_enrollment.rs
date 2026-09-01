use std::sync::Arc;

use super::DaemonCanonicalProviderService;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;

impl DaemonCanonicalProviderService {
    /// Returns the reader-only daemon control facade when native enrollment is available.
    pub(crate) fn credential_enrollment_control(
        &self,
    ) -> Option<Arc<DaemonProviderCredentialEnrollmentControl>> {
        self.credential_enrollment_control.clone()
    }
}
