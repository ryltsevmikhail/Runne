use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;

use super::{DaemonCanonicalProviderService, DaemonError};
use std::sync::Arc;

pub(super) async fn finish_composition(
    service: &Arc<DaemonCanonicalProviderService>,
    deferred: bool,
    has_effect_source: bool,
) -> Result<(), DaemonError> {
    #[cfg(any(
        all(test, unix),
        all(
            feature = "desktop-protected",
            target_os = "macos",
            target_arch = "aarch64"
        )
    ))]
    service.install_remote_verification()?;
    reconcile_initial(service.as_ref(), deferred, has_effect_source)?;
    reconcile_secondary_initial(service.as_ref(), has_effect_source)?;
    service.recover_pending().await
}

pub(super) fn reconcile_initial(
    service: &DaemonCanonicalProviderService,
    deferred: bool,
    has_effect_source: bool,
) -> Result<(), DaemonError> {
    match (deferred, service.credential_readback.as_deref()) {
        (true, _) => Ok(()),
        (false, Some(reader)) => {
            CredentialEnrollmentRecoveryGateway::new(service.credential_store.as_ref(), reader)
                .reconcile_online(chrono::Utc::now().timestamp())
                .map_err(|_| {
                    DaemonError::Bootstrap("credential enrollment recovery unavailable".into())
                })
        }
        (false, None) if !has_effect_source => Err(DaemonError::Bootstrap(
            "provider credential reader unavailable".into(),
        )),
        (false, None) => Ok(()),
    }
}

pub(super) fn reconcile_secondary_initial(
    service: &DaemonCanonicalProviderService,
    has_effect_source: bool,
) -> Result<(), DaemonError> {
    let Some(route) = service.secondary_profile.as_ref() else {
        return Ok(());
    };
    match (
        route.defer_credential_reconciliation,
        route.credential_readback.as_deref(),
    ) {
        (true, _) => Ok(()),
        (false, Some(reader)) => {
            CredentialEnrollmentRecoveryGateway::new(route.credential_store.as_ref(), reader)
                .reconcile_online(chrono::Utc::now().timestamp())
                .map_err(|_| {
                    DaemonError::Bootstrap(
                        "secondary credential enrollment recovery unavailable".into(),
                    )
                })
        }
        (false, None) if !has_effect_source => Err(DaemonError::Bootstrap(
            "secondary provider credential reader unavailable".into(),
        )),
        (false, None) => Ok(()),
    }
}
