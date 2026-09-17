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
        #[cfg(target_os = "macos")]
        {
            self.terminate_retained_writer();
            self.claim_measurements.take();
            self.credential_service.take();
            self.credential_service_configuration.take();
            self.deferred_control.take();
        }
        self.broker.take();
        self.live.take();
        self.session.take()
    }

    /// Off macOS the V3 loop holds no credential enrollment session; only the
    /// live-session authority is released before the shutdown acknowledgement.
    #[cfg(all(unix, not(all(target_os = "macos", target_arch = "aarch64"))))]
    pub(super) fn revoke_shutdown_authorization(&mut self) {
        self.live.take();
    }
}
