use std::sync::Arc;

use super::credential_reader::CredentialBoundary;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
use crate::error::DaemonError;

pub(super) fn compose(
    credentials: &mut CredentialBoundary,
    runtime_authority: [u8; 16],
    database_generation: u64,
) -> Result<Option<Arc<DaemonProviderCredentialEnrollmentControl>>, DaemonError> {
    let Some(authorities) = credentials.enrollment_authorities.take() else {
        return Ok(None);
    };
    let Some(readback) = credentials.readback.clone() else {
        return Ok(None);
    };
    DaemonProviderCredentialEnrollmentControl::new(
        Arc::clone(&credentials.store),
        readback,
        authorities.measurements,
        authorities.store,
        runtime_authority,
        database_generation,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credentials.credential_service.clone(),
    )
    .map(|control| Some(Arc::new(control)))
    .map_err(|_| DaemonError::Bootstrap("provider credential control unavailable".into()))
}
