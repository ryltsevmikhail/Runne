#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
use super::*;

#[cfg(any(
    all(feature = "desktop-protected", target_os = "linux"),
    all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )
))]
impl DaemonProviderCredentialEnrollmentControl {
    pub(crate) fn start_protected_session_with_controls(
        self: &Arc<Self>,
        keys: &runne_api::ProtectedActivationKeys,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        rendezvous: super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous,
        controls: Vec<Arc<DaemonProviderCredentialEnrollmentControl>>,
        #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "desktop-protected"))]
        installed_facts: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    ) -> Result<DaemonProtectedCredentialEnrollmentSession, ProviderCredentialEnrollmentHostError>
    {
        let facts = ProtectedEnrollmentSessionFacts::from_owned(
            owned,
            self.runtime_authority,
            self.database_generation,
        )?;
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let mut session = DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts.clone(),
            rendezvous,
        )?;
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        let mut session = DaemonProtectedCredentialEnrollmentSession::new(
            Arc::clone(self),
            keys,
            facts.clone(),
            rendezvous,
            Some(installed_facts),
        )?;
        session.set_http_controls(controls);
        crate::protected_activation::enrollment_control_fanout::publish(
            &session.http_controls(),
            &facts,
        )?;
        Ok(session)
    }
}
