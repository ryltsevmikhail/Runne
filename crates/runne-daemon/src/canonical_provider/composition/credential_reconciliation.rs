use crate::application::provider_credential_enrollment::CredentialEnrollmentRecoveryGateway;

use super::{DaemonCanonicalProviderService, DaemonError};

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
