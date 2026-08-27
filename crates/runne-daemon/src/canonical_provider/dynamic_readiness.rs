use runne_api::ProviderActivationReadinessV1;
use runne_provider::{CredentialReadinessDisposition, CredentialSafeSnapshot};

mod service;

/// Narrows the durable lifecycle projection to the released V1 readiness enum.
///
/// V1 cannot represent stale or invariant lifecycle observations. Those states
/// fail closed instead of advertising a potentially usable model.
pub(super) const fn from_safe_snapshot(
    snapshot: &CredentialSafeSnapshot,
) -> ProviderActivationReadinessV1 {
    match snapshot.readiness() {
        CredentialReadinessDisposition::Ready if snapshot.configured() => {
            ProviderActivationReadinessV1::Ready
        }
        CredentialReadinessDisposition::AccessDenied => {
            ProviderActivationReadinessV1::CredentialAccessDenied
        }
        CredentialReadinessDisposition::Missing => ProviderActivationReadinessV1::CredentialMissing,
        CredentialReadinessDisposition::Ready
        | CredentialReadinessDisposition::Stale
        | CredentialReadinessDisposition::Unavailable
        | CredentialReadinessDisposition::Unsupported
        | CredentialReadinessDisposition::Conflict
        | CredentialReadinessDisposition::InvariantFailure => {
            ProviderActivationReadinessV1::SecureStoreUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::{
        CredentialLifecycleRevision, CredentialReadinessRevision, CredentialVerificationSnapshot,
        ProviderId,
    };

    fn snapshot(
        configured: bool,
        readiness: CredentialReadinessDisposition,
    ) -> CredentialSafeSnapshot {
        CredentialSafeSnapshot::new(
            ProviderId::new("openai").unwrap(),
            configured,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialReadinessRevision::new(1).unwrap(),
            readiness,
            1,
            CredentialVerificationSnapshot::not_verified(),
        )
        .unwrap()
    }

    #[test]
    fn missing_credential_never_advertises_a_ready_provider() {
        assert_eq!(
            from_safe_snapshot(&snapshot(false, CredentialReadinessDisposition::Missing)),
            ProviderActivationReadinessV1::CredentialMissing
        );
    }

    #[test]
    fn only_current_configured_readiness_is_ready() {
        assert_eq!(
            from_safe_snapshot(&snapshot(true, CredentialReadinessDisposition::Ready)),
            ProviderActivationReadinessV1::Ready
        );
        assert_eq!(
            from_safe_snapshot(&snapshot(false, CredentialReadinessDisposition::Ready)),
            ProviderActivationReadinessV1::SecureStoreUnavailable
        );
    }
}
