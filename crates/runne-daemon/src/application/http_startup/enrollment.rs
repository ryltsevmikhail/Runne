use std::sync::Arc;

use super::*;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;

pub(super) struct EnrollmentHttpComposition {
    pub(super) control: Option<Arc<DaemonProviderCredentialEnrollmentControl>>,
    pub(super) routes: Option<axum::Router>,
    pub(super) runtime_capabilities: &'static [&'static str],
}

pub(super) fn compose(
    provider_service: Option<&Arc<super::super::DaemonCanonicalProviderService>>,
    protected: bool,
    root_admission_keys: Option<&runne_api::ProtectedActivationKeys>,
    capability: Option<&crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
) -> Result<EnrollmentHttpComposition, DaemonError> {
    let control = provider_service.and_then(|service| service.credential_enrollment_control());
    let mounted = mounted(
        protected,
        root_admission_keys.is_some(),
        qualified_release(capability),
        control.is_some(),
    )?;
    let runtime_capabilities = super::provider_credentials::runtime_capabilities(
        protected,
        root_admission_keys.is_some(),
        mounted,
    );
    let routes = routes(control.as_ref(), mounted);
    Ok(EnrollmentHttpComposition {
        control,
        routes,
        runtime_capabilities,
    })
}

pub(super) fn qualified_release(
    capability: Option<&crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
) -> bool {
    capability.is_some_and(
        crate::protected_activation::VerifiedProtectedEnrollmentCapability::is_qualified,
    )
}

pub(super) fn mounted(
    protected: bool,
    has_root_keys: bool,
    qualified_release: bool,
    has_control: bool,
) -> Result<bool, DaemonError> {
    if protected && qualified_release && !has_control {
        return Err(DaemonError::Bootstrap(
            "qualified enrollment release requires canonical credential control".to_owned(),
        ));
    }
    Ok(protected && has_root_keys && qualified_release && has_control)
}

pub(super) fn routes(
    control: Option<&Arc<DaemonProviderCredentialEnrollmentControl>>,
    mounted: bool,
) -> Option<axum::Router> {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    {
        control.filter(|_| mounted).map(|control| {
            control.http_enrollment_router(Arc::new(|| chrono::Utc::now().timestamp()))
        })
    }
    #[cfg(not(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )))]
    {
        let _ = (control, mounted);
        None
    }
}

#[cfg(test)]
mod tests;
