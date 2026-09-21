#[cfg(all(unix, target_os = "macos", target_arch = "aarch64"))]
impl V3EnrollmentRuntime {
    /// Releases runtime-local enrollment resources and transfers the session
    /// whose drop revokes HTTP admission before the shutdown acknowledgement.
    /// Shared credential-service registration is owned separately.
    pub(super) fn revoke_shutdown_authorization(
        &mut self,
    ) -> Option<
        crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
    >{
        self.terminate_retained_writer();
        self.claim_measurements.take();
        self.credential_service.take();
        self.credential_service_configuration.take();
        self.deferred_control.take();
        self.broker.take();
        self.live.take();
        self.session.take()
    }
}
