use std::sync::Arc;

use super::DaemonCanonicalProviderService;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use crate::canonical_provider::readiness::credential_access_policy;
#[cfg(any(
    all(test, unix),
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_secure_store::ProviderCredentialVerificationMaterializer;

impl DaemonCanonicalProviderService {
    /// Returns the reader-only daemon control facade when native enrollment is available.
    pub(crate) fn credential_enrollment_control(
        &self,
    ) -> Option<Arc<DaemonProviderCredentialEnrollmentControl>> {
        self.credential_enrollment_control.clone()
    }

    /// Returns enrollment control only for an exact selected provider realm.
    pub(crate) fn credential_enrollment_control_for_provider(
        &self,
        provider_id: &str,
    ) -> Option<Arc<DaemonProviderCredentialEnrollmentControl>> {
        if self.provider_id.as_ref() == provider_id {
            return self.credential_enrollment_control.clone();
        }
        self.secondary_profile
            .as_ref()
            .filter(|route| route.provider_id.as_ref() == provider_id)
            .and_then(|route| route.credential_enrollment_control.clone())
    }

    /// Returns only the separately composed credential controls for session sync.
    pub(crate) fn credential_enrollment_controls(
        &self,
    ) -> Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)> {
        let mut controls = Vec::with_capacity(2);
        if let Some(control) = self.credential_enrollment_control.clone() {
            controls.push((self.provider_id.to_string(), control));
        }
        if let Some(route) = self.secondary_profile.as_ref()
            && let Some(control) = route.credential_enrollment_control.clone()
        {
            controls.push((route.provider_id.to_string(), control));
        }
        controls
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    /// Builds the reader-only remote verification materializer for this service.
    ///
    /// The authority is the same sealed issuer used for the service's
    /// lifecycle store; callers still need a store-issued remote capability.
    pub(crate) fn remote_verification_materializer(
        &self,
    ) -> Result<Arc<dyn ProviderCredentialVerificationMaterializer>, crate::error::DaemonError>
    {
        let credential =
            runne_secure_store::ProviderCredentialId::from_account(self.provider_id.as_ref())
                .ok_or_else(|| {
                    crate::error::DaemonError::Config("provider credential is not closed".into())
                })?;
        let access = credential_access_policy(credential)?;
        let Some(authority) = self.enrollment_store_authority.clone() else {
            return Err(crate::error::DaemonError::Bootstrap(
                "remote verification authority unavailable".into(),
            ));
        };
        Ok(runne_secure_store::native_verification_materializer(
            authority, access,
        ))
    }

    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    /// Installs the explicit protected-path remote quota verifier.
    pub(crate) fn install_remote_verification(&self) -> Result<(), crate::error::DaemonError> {
        let Some(control) = self.credential_enrollment_control.clone() else {
            return Ok(());
        };
        let provider = runne_api::ProviderCredentialProviderV2::parse(self.provider_id.as_ref())
            .ok_or_else(|| crate::error::DaemonError::Config("provider is not closed".into()))?;
        let materializer = self.remote_verification_materializer()?;
        let transport = Arc::new(
            runne_daemon_chat_completions_effect::ReqwestQuotaRefreshTransport::new().map_err(
                |_| {
                    crate::error::DaemonError::Bootstrap(
                        "quota refresh transport unavailable".into(),
                    )
                },
            )?,
        );
        let sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = self.quota_store.clone();
        let verifier = crate::application::provider_credential_verification::RemoteProviderCredentialVerification::new(
            Arc::clone(&self.credential_store),
            control.measurement_authority(),
            control.operation_handle_issuer(),
            materializer,
            transport,
            sink,
            provider,
            Some(self.model_id.as_ref().to_owned()),
            Some(self.credential_store.clone()),
        );
        control
            .install_verification(Arc::new(verifier))
            .map_err(|_| {
                crate::error::DaemonError::Bootstrap(
                    "quota verification host already installed".into(),
                )
            })
    }
}
