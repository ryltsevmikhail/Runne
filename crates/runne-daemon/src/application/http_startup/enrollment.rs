use std::sync::Arc;

use super::*;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;

pub(super) struct EnrollmentHttpComposition {
    pub(super) control: Option<Arc<DaemonProviderCredentialEnrollmentControl>>,
    pub(super) credential_enrollment_controls:
        Vec<(String, Arc<DaemonProviderCredentialEnrollmentControl>)>,
    pub(super) routes: Option<axum::Router>,
    pub(super) runtime_capabilities: &'static [&'static str],
}

pub(super) fn compose(
    provider_service: Option<&Arc<super::super::DaemonCanonicalProviderService>>,
    standalone_control: Option<Arc<DaemonProviderCredentialEnrollmentControl>>,
    protected: bool,
    root_admission_keys: Option<&runne_api::ProtectedActivationKeys>,
    capability: Option<&crate::protected_activation::VerifiedProtectedEnrollmentCapability>,
) -> Result<EnrollmentHttpComposition, DaemonError> {
    let control = provider_service
        .and_then(|service| service.credential_enrollment_control())
        .or(standalone_control);
    let background_control = provider_service.and_then(|service| {
        service.credential_enrollment_control_for_provider("openai-background")
    });
    let credential_enrollment_controls = provider_service
        .map(|service| service.credential_enrollment_controls())
        .unwrap_or_default();
    let has_control = control.is_some() || background_control.is_some();
    let mounted = mounted(
        protected,
        root_admission_keys.is_some(),
        qualified_release(capability),
        has_control,
    )?;
    let runtime_capabilities = super::provider_credentials::runtime_capabilities(
        protected,
        root_admission_keys.is_some(),
        mounted,
    );
    let routes = routes(
        control.as_ref(),
        mounted,
        protected && root_admission_keys.is_some(),
    );
    let background_routes = provider_routes(
        background_control.as_ref(),
        "openai-background",
        mounted,
        protected && root_admission_keys.is_some(),
    );
    let routes = merge_routes(routes, background_routes);
    Ok(EnrollmentHttpComposition {
        control,
        credential_enrollment_controls,
        routes,
        runtime_capabilities,
    })
}

fn merge_routes(
    primary: Option<axum::Router>,
    background: Option<axum::Router>,
) -> Option<axum::Router> {
    match (primary, background) {
        (Some(primary), Some(background)) => Some(primary.merge(background)),
        (Some(routes), None) | (None, Some(routes)) => Some(routes),
        (None, None) => None,
    }
}

fn provider_routes(
    control: Option<&Arc<DaemonProviderCredentialEnrollmentControl>>,
    provider: &'static str,
    mounted: bool,
    protected_admission: bool,
) -> Option<axum::Router> {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    {
        let _ = protected_admission;
        control.filter(|_| mounted).map(|control| {
            control.http_enrollment_router_for_provider(
                provider,
                Arc::new(|| chrono::Utc::now().timestamp()),
            )
        })
    }
    #[cfg(not(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    )))]
    {
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        {
            let _ = mounted;
            control.filter(|_| protected_admission).map(|control| {
                control.http_enrollment_router_for_provider(
                    provider,
                    Arc::new(|| chrono::Utc::now().timestamp()),
                )
            })
        }
        #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
        {
            let _ = (control, provider, mounted, protected_admission);
            None
        }
    }
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
    protected_admission: bool,
) -> Option<axum::Router> {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    {
        let _ = protected_admission;
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
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        {
            let _ = mounted;
            control.filter(|_| protected_admission).map(|control| {
                control.http_enrollment_router(Arc::new(|| chrono::Utc::now().timestamp()))
            })
        }
        #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
        {
            let _ = (control, mounted, protected_admission);
            None
        }
    }
}

#[cfg(test)]
mod tests;
