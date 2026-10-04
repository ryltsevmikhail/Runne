use std::sync::Arc;

use super::DaemonProviderCredentialEnrollmentControl;

#[cfg(all(
    feature = "desktop-protected",
    any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
))]
impl DaemonProviderCredentialEnrollmentControl {
    pub(crate) fn http_enrollment_router_for_provider(
        self: &Arc<Self>,
        provider: &'static str,
        now_high_water: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> axum::Router {
        let host = super::super::DaemonProviderCredentialEnrollmentHttpHost::new(
            Arc::clone(self),
            self.http_authority_verifier.clone(),
            now_high_water,
        );
        let resolver =
            super::super::http_admission_resolver::LiveCredentialHttpAdmissionResolver::new(
                self.http_authority_issuer.clone(),
                Arc::clone(&self.http_facts),
            );
        runne_http::provider_credential_enrollment_router_for_provider(
            runne_http::ProviderCredentialEnrollmentHttpState::with_admission_resolver(
                host, resolver,
            ),
            provider,
        )
    }
}
