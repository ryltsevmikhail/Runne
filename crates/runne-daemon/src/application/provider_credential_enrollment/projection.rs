#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 host composes this safe mapper after Task 11 owns writer handoff"
    )
)]

use runne_api::{
    ProviderCredentialLastDispositionV2, ProviderCredentialPendingOperationV2,
    ProviderCredentialProviderV2, ProviderCredentialReadinessV2, ProviderCredentialSafeSnapshotV2,
    ProviderCredentialStateV2, ProviderCredentialVerificationStateV2,
};
use runne_provider::{
    CredentialReadinessDisposition, CredentialSafeSnapshot, CredentialVerificationKind,
    CredentialVerificationResult,
};

/// Converts the store-owned metadata projection into the exact public V2 DTO.
pub(super) fn safe_snapshot(
    snapshot: CredentialSafeSnapshot,
) -> Result<ProviderCredentialSafeSnapshotV2, runne_api::ProviderCredentialEnrollmentHostError> {
    let verification = snapshot.verification();
    ProviderCredentialSafeSnapshotV2::new(
        provider(snapshot.provider().as_str())?,
        credential_state(snapshot.configured(), snapshot.readiness()),
        readiness(snapshot.readiness()),
        snapshot.lifecycle_revision().get(),
        snapshot.readiness_revision().get(),
        snapshot.observed_at_high_water(),
        verification_state(
            verification.kind(),
            verification.result(),
            verification.is_pending(),
        ),
        verification
            .verifier_revision()
            .map(runne_provider::CredentialVerifierRevision::get)
            .unwrap_or(0),
        verification
            .is_pending()
            .then_some(ProviderCredentialPendingOperationV2::Verifying),
        false,
        None::<ProviderCredentialLastDispositionV2>,
    )
    .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn provider(
    provider: &str,
) -> Result<ProviderCredentialProviderV2, runne_api::ProviderCredentialEnrollmentHostError> {
    ProviderCredentialProviderV2::parse(provider)
        .ok_or(runne_api::ProviderCredentialEnrollmentHostError::InvariantViolation)
}

#[cfg(test)]
mod background_identity_tests {
    use super::provider;
    use runne_api::ProviderCredentialProviderV2;

    #[test]
    fn safe_projection_parses_background_credential_identity() {
        assert_eq!(
            provider("openai-background").unwrap(),
            ProviderCredentialProviderV2::OpenAiBackground
        );
    }
}

fn credential_state(
    configured: bool,
    readiness: CredentialReadinessDisposition,
) -> ProviderCredentialStateV2 {
    match readiness {
        CredentialReadinessDisposition::AccessDenied => ProviderCredentialStateV2::AccessDenied,
        CredentialReadinessDisposition::Unsupported => ProviderCredentialStateV2::Unsupported,
        CredentialReadinessDisposition::Unavailable | CredentialReadinessDisposition::Conflict => {
            ProviderCredentialStateV2::Unavailable
        }
        CredentialReadinessDisposition::InvariantFailure => ProviderCredentialStateV2::Unavailable,
        _ if configured => ProviderCredentialStateV2::Configured,
        _ => ProviderCredentialStateV2::Missing,
    }
}

fn readiness(value: CredentialReadinessDisposition) -> ProviderCredentialReadinessV2 {
    match value {
        CredentialReadinessDisposition::Ready => ProviderCredentialReadinessV2::Ready,
        CredentialReadinessDisposition::Missing => ProviderCredentialReadinessV2::Missing,
        CredentialReadinessDisposition::Stale => ProviderCredentialReadinessV2::Stale,
        CredentialReadinessDisposition::Unavailable => ProviderCredentialReadinessV2::Unavailable,
        CredentialReadinessDisposition::Unsupported => ProviderCredentialReadinessV2::Unsupported,
        CredentialReadinessDisposition::AccessDenied => ProviderCredentialReadinessV2::AccessDenied,
        CredentialReadinessDisposition::Conflict => ProviderCredentialReadinessV2::Conflict,
        CredentialReadinessDisposition::InvariantFailure => {
            ProviderCredentialReadinessV2::InvariantFailure
        }
    }
}

fn verification_state(
    kind: Option<CredentialVerificationKind>,
    result: Option<CredentialVerificationResult>,
    pending: bool,
) -> ProviderCredentialVerificationStateV2 {
    match (kind, result, pending) {
        (None, None, false) => ProviderCredentialVerificationStateV2::NotVerified,
        (_, None, true) => ProviderCredentialVerificationStateV2::Stale,
        (
            Some(CredentialVerificationKind::Local),
            Some(CredentialVerificationResult::Verified),
            _,
        ) => ProviderCredentialVerificationStateV2::LocalVerified,
        (
            Some(CredentialVerificationKind::Remote),
            Some(CredentialVerificationResult::Verified),
            _,
        ) => ProviderCredentialVerificationStateV2::RemoteVerified,
        (_, Some(CredentialVerificationResult::Failed), _) => {
            ProviderCredentialVerificationStateV2::Failed
        }
        (_, Some(CredentialVerificationResult::Unsupported), _) => {
            ProviderCredentialVerificationStateV2::Unsupported
        }
        (_, Some(CredentialVerificationResult::Unavailable), _) => {
            ProviderCredentialVerificationStateV2::Unavailable
        }
        (_, Some(CredentialVerificationResult::AccessDenied), _) => {
            ProviderCredentialVerificationStateV2::AccessDenied
        }
        (_, Some(CredentialVerificationResult::Conflict), _) => {
            ProviderCredentialVerificationStateV2::Stale
        }
        _ => ProviderCredentialVerificationStateV2::Stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::{
        CredentialLifecycleRevision, CredentialReadinessRevision, CredentialVerificationSnapshot,
        CredentialVerifierRevision, ProviderId,
    };

    #[test]
    fn safe_projection_maps_ready_local_verification_without_internal_metadata() {
        let verification = CredentialVerificationSnapshot::completed(
            CredentialVerificationKind::Local,
            CredentialVerificationResult::Verified,
            CredentialVerifierRevision::new(3).unwrap(),
            12,
        )
        .unwrap();
        let value = CredentialSafeSnapshot::new(
            ProviderId::new("openai").unwrap(),
            true,
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialReadinessRevision::new(2).unwrap(),
            CredentialReadinessDisposition::Ready,
            12,
            verification,
        )
        .unwrap();

        let projection = safe_snapshot(value).unwrap();
        assert_eq!(
            projection.provider_id(),
            ProviderCredentialProviderV2::OpenAi
        );
        assert_eq!(
            projection.credential_state(),
            ProviderCredentialStateV2::Configured
        );
        assert_eq!(
            projection.verification_state(),
            ProviderCredentialVerificationStateV2::LocalVerified
        );
        assert_eq!(projection.verification_revision(), 3);
    }
}
