use runne_api::{
    ProviderCredentialEnrollmentHostError, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2,
};
use runne_provider::{
    CredentialOperationAction, CredentialOperationSnapshot, CredentialOperationState,
};

use super::{
    broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer,
};

/// Projects one caller-owned durable operation without exposing native metadata.
pub(super) fn snapshot(
    operation: CredentialOperationSnapshot,
    handles: &ProviderCredentialOperationHandleIssuer,
    readiness_revision: u64,
    rendezvous: &PendingBrokerRendezvousRegistry,
    now_high_water: i64,
) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
    let handle = handles.issue(operation.operation_id());
    let rendezvous_id = (operation.state() == CredentialOperationState::Prepared
        && rendezvous.has_live(operation.operation_id(), now_high_water))
    .then(|| handles.issue_broker_rendezvous_id(operation.operation_id()));
    ProviderCredentialOperationSnapshotV2::new(
        handle,
        rendezvous_id,
        provider(operation.provider().as_str())?,
        kind(operation.action())?,
        state(operation.state()),
        operation.lifecycle_revision().get(),
        readiness_revision,
        false,
        None,
    )
    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn provider(
    value: &str,
) -> Result<ProviderCredentialProviderV2, ProviderCredentialEnrollmentHostError> {
    ProviderCredentialProviderV2::parse(value)
        .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)
}

fn kind(
    action: CredentialOperationAction,
) -> Result<ProviderCredentialOperationKindV2, ProviderCredentialEnrollmentHostError> {
    match action {
        CredentialOperationAction::Pair => Ok(ProviderCredentialOperationKindV2::Pair),
        CredentialOperationAction::Revoke => Ok(ProviderCredentialOperationKindV2::Revoke),
        CredentialOperationAction::MigrateLegacy => {
            Ok(ProviderCredentialOperationKindV2::MigrateLegacy)
        }
        CredentialOperationAction::RetiredVersionCleanup
        | CredentialOperationAction::LegacySourceCleanup
        | CredentialOperationAction::WriterIdentityMigrationEffect
        | CredentialOperationAction::WriterIdentityMigrationVerify => {
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        }
    }
}

const fn state(value: CredentialOperationState) -> ProviderCredentialOperationStateV2 {
    match value {
        CredentialOperationState::Prepared => ProviderCredentialOperationStateV2::Prepared,
        CredentialOperationState::Claimed => ProviderCredentialOperationStateV2::Claimed,
        CredentialOperationState::NativeEffectObserved => {
            ProviderCredentialOperationStateV2::NativeEffectObserved
        }
        CredentialOperationState::ReadbackVerified => {
            ProviderCredentialOperationStateV2::ReadbackVerified
        }
        CredentialOperationState::Completed => ProviderCredentialOperationStateV2::Completed,
        CredentialOperationState::Failed => ProviderCredentialOperationStateV2::Failed,
        CredentialOperationState::Expired => ProviderCredentialOperationStateV2::Expired,
        CredentialOperationState::Cancelled => ProviderCredentialOperationStateV2::Cancelled,
        CredentialOperationState::Tombstoned => ProviderCredentialOperationStateV2::Tombstoned,
    }
}

#[cfg(test)]
mod tests {
    use super::provider;
    use runne_api::ProviderCredentialProviderV2;

    #[test]
    fn background_operation_projection_keeps_its_separate_provider_account() {
        assert_eq!(
            provider("openai-background").unwrap(),
            ProviderCredentialProviderV2::OpenAiBackground
        );
    }
}
