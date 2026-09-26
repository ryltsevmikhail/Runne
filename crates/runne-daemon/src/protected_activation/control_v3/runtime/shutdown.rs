#[cfg(unix)]
impl V3EnrollmentRuntime {
    /// Releases runtime-local enrollment resources and transfers the session
    /// whose drop revokes HTTP admission before the shutdown acknowledgement.
    /// Shared credential-service registration is owned separately.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
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

    /// Off macOS the V3 loop holds no credential enrollment session; only the
    /// live-session authority is released before the shutdown acknowledgement.
    #[cfg(all(unix, not(all(target_os = "macos", target_arch = "aarch64"))))]
    pub(super) fn revoke_shutdown_authorization(&mut self) {
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        if let Some(session) = self.session.as_ref() {
            session.clear_http_facts();
        }
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        {
            let _ = self.terminate_retained_writer();
            self.linux_writer.take();
            self.linux_writer_capability.take();
        }
        self.live.take();
        #[cfg(target_os = "linux")]
        self.session.take();
    }
}
