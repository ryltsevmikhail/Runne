//! One-shot install guard for the daemon-local verification readback.

#![cfg(any(
    test,
    all(feature = "desktop-protected", target_os = "linux"),
    all(target_os = "macos", feature = "desktop-protected")
))]

use std::sync::{Arc, OnceLock};

use runne_api::ProviderCredentialEnrollmentHostError;

#[cfg_attr(
    not(any(test, all(target_os = "macos", feature = "desktop-protected"))),
    expect(
        dead_code,
        reason = "local readback install is test-driven until the D1 Linux composition slice mounts it"
    )
)]
pub(super) fn install_local_readback_once(
    slot: &OnceLock<Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>>,
    readback: Arc<dyn runne_secure_store::ProviderCredentialVerificationReadback>,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if let Some(existing) = slot.get() {
        return if Arc::ptr_eq(existing, &readback) {
            Ok(())
        } else {
            Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
        };
    }
    slot.set(readback)
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}
