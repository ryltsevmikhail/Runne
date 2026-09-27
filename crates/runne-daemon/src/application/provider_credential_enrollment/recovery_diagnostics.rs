use runne_api::ProviderCredentialEnrollmentHostError as HostError;
use runne_secure_store::SecureStoreError;

use crate::protected_activation::linux_pair_diagnostics::record;

pub(super) fn map_readback_error(error: SecureStoreError) -> HostError {
    let (stage, mapped) = classify_readback_error(&error);
    record(stage, false);
    mapped
}

fn classify_readback_error(error: &SecureStoreError) -> (&'static str, HostError) {
    match error {
        SecureStoreError::CredentialAccessDenied
        | SecureStoreError::CredentialIdentityMismatch
        | SecureStoreError::CredentialAclMigrationRequired => {
            ("recovery_readback_access_denied", HostError::AccessDenied)
        }
        SecureStoreError::UnsupportedSecureStoreBackend => {
            ("recovery_readback_unsupported", HostError::Unsupported)
        }
        SecureStoreError::CorruptProviderCredential => {
            ("recovery_readback_corrupt", HostError::InvariantViolation)
        }
        SecureStoreError::ProviderCredentialOperationFailed => {
            ("recovery_readback_conflict", HostError::Conflict)
        }
        SecureStoreError::Unavailable => ("recovery_readback_unavailable", HostError::Unavailable),
        SecureStoreError::OperationFailed(_) => {
            ("recovery_readback_operation_failed", HostError::Unavailable)
        }
        SecureStoreError::InvalidProviderCredential => {
            ("recovery_readback_invalid", HostError::Unavailable)
        }
        SecureStoreError::ProviderCredentialNotFound => {
            ("recovery_readback_not_found", HostError::Unavailable)
        }
        SecureStoreError::CredentialEnrollmentIncomplete => (
            "recovery_readback_enrollment_incomplete",
            HostError::Unavailable,
        ),
        SecureStoreError::CredentialMigrationIncomplete => (
            "recovery_readback_migration_incomplete",
            HostError::Unavailable,
        ),
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable => {
            ("recovery_readback_source_revision", HostError::Unavailable)
        }
        _ => (
            "recovery_readback_other_secure_store",
            HostError::Unavailable,
        ),
    }
}

pub(super) fn record_result(stage: &'static str, succeeded: bool) {
    record(stage, succeeded);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readback_errors_map_to_closed_classes() {
        let cases = [
            (
                SecureStoreError::CredentialAccessDenied,
                "recovery_readback_access_denied",
                HostError::AccessDenied,
            ),
            (
                SecureStoreError::UnsupportedSecureStoreBackend,
                "recovery_readback_unsupported",
                HostError::Unsupported,
            ),
            (
                SecureStoreError::CorruptProviderCredential,
                "recovery_readback_corrupt",
                HostError::InvariantViolation,
            ),
            (
                SecureStoreError::ProviderCredentialOperationFailed,
                "recovery_readback_conflict",
                HostError::Conflict,
            ),
            (
                SecureStoreError::Unavailable,
                "recovery_readback_unavailable",
                HostError::Unavailable,
            ),
        ];
        for (error, expected_stage, expected_error) in cases {
            let (stage, mapped) = classify_readback_error(&error);
            assert_eq!(stage, expected_stage);
            assert_eq!(mapped, expected_error);
        }
    }
}
