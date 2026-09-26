use super::ConfirmedInstalledNativeEnrollment;

impl ConfirmedInstalledNativeEnrollment {
    /// Confirms measured Linux images against the retained signed tuple.
    ///
    /// Runtime authority is established independently by the managed
    /// supervisor's verified readiness transcript; the enrollment launch
    /// authority is a per-launch nonce and is not signed installation data.
    #[must_use]
    pub fn matches_linux_signed_installation_images(
        &self,
        facts: &runne_api::provider_credential_enrollment::linux_activation_policy::LinuxInstallationFacts,
    ) -> bool {
        self.admission.desktop_sha256 == facts.desktop_image_digest
            && self.admission.writer_sha256 == facts.writer_image_digest
            && self.admission.daemon_sha256 == facts.daemon_image_digest
    }
}
