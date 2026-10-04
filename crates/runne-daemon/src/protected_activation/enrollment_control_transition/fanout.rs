use std::sync::Arc;

use super::EnrollmentControlComposition;
use crate::application::provider_credential_enrollment::{
    DaemonProviderCredentialEnrollmentControl, ProtectedEnrollmentSessionFacts,
};

impl EnrollmentControlComposition {
    pub(crate) fn with_enrollment_controls(
        mut self,
        controls: Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)>,
    ) -> Self {
        self.enrollment_controls = controls;
        self
    }

    pub(in crate::protected_activation) fn publish_http_facts(
        &self,
        facts: &ProtectedEnrollmentSessionFacts,
    ) -> Result<(), runne_api::ProviderCredentialEnrollmentHostError> {
        super::super::enrollment_control_fanout::publish(&self.controls(), facts)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(in crate::protected_activation) fn publish_verified_v2_status(
        &self,
        owned: &runne_api::ProtectedOwnedLaunchV2,
        release: [u8; 32],
        peer: [u8; 32],
        supervisor: u64,
    ) -> Result<(), runne_api::ProviderCredentialEnrollmentHostError> {
        super::super::enrollment_control_fanout::publish_v2(
            &self.controls(),
            owned,
            self.installation_identity_digest,
            release,
            peer,
            supervisor,
        )
    }

    pub(in crate::protected_activation) fn clear_http_facts(&self, session: [u8; 16]) {
        super::super::enrollment_control_fanout::clear(&self.controls(), session);
    }

    pub(in crate::protected_activation) fn session_controls(
        &self,
    ) -> Vec<Arc<DaemonProviderCredentialEnrollmentControl>> {
        self.controls()
    }

    fn controls(&self) -> Vec<Arc<DaemonProviderCredentialEnrollmentControl>> {
        let mut controls = self
            .enrollment_controls
            .iter()
            .map(|(_, control)| Arc::clone(control))
            .collect::<Vec<_>>();
        if let Some(primary) = self.enrollment_control.as_ref()
            && !controls.iter().any(|control| Arc::ptr_eq(control, primary))
        {
            controls.push(Arc::clone(primary));
        }
        controls
    }
}
