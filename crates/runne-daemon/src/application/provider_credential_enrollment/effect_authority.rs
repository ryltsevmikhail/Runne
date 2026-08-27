use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{CredentialLifecycleError, CredentialOperationSnapshot};

/// Private, move-only authority for the single durable begin effect.
#[must_use = "an accepted effect authority must be consumed or deliberately dropped"]
#[allow(dead_code)]
pub(super) struct ProviderCredentialEffectAuthority {
    operation: CredentialOperationSnapshot,
}

#[allow(dead_code)]
impl ProviderCredentialEffectAuthority {
    pub(super) const fn from_fresh_winner(operation: CredentialOperationSnapshot) -> Self {
        Self { operation }
    }

    /// Consumes the authority after durable admission without a second begin effect.
    pub(super) fn consume(self) -> CredentialOperationSnapshot {
        self.operation
    }

    #[cfg(test)]
    pub(super) const fn operation(&self) -> &CredentialOperationSnapshot {
        &self.operation
    }
}

#[allow(dead_code)]
pub(super) fn map_store(error: CredentialLifecycleError) -> ProviderCredentialEnrollmentHostError {
    match error {
        CredentialLifecycleError::Conflict | CredentialLifecycleError::StaleLease => {
            ProviderCredentialEnrollmentHostError::Conflict
        }
        CredentialLifecycleError::LifecycleClosed => {
            ProviderCredentialEnrollmentHostError::Unsupported
        }
        CredentialLifecycleError::InvalidInput => {
            ProviderCredentialEnrollmentHostError::InvalidRequest
        }
        CredentialLifecycleError::CorruptState => {
            ProviderCredentialEnrollmentHostError::InvariantViolation
        }
        _ => ProviderCredentialEnrollmentHostError::Unavailable,
    }
}
