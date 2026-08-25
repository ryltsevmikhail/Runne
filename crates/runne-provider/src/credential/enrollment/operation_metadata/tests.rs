use runne_domain::id::{CommandId, IdempotencyKey};

use super::*;
use crate::credential::enrollment::{
    CredentialOperationAction, CredentialOperationSnapshot, CredentialOperationState,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_snapshot_rejects_incomplete_and_out_of_order_v24_evidence() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let prepared = metadata();
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Prepared,
            Some(version.clone()),
            prepared.clone(),
        )
        .is_ok()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Prepared,
            Some(version.clone()),
            prepared.clone().with_claim(digest(2), digest(3)),
        )
        .is_err()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Claimed,
            Some(version.clone()),
            prepared.clone(),
        )
        .is_err()
    );
    let claimed = prepared.clone().with_claim(digest(2), digest(3));
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Claimed,
            Some(version.clone()),
            claimed.clone(),
        )
        .is_ok()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::NativeEffectObserved,
            Some(version.clone()),
            claimed.clone(),
        )
        .is_err()
    );
    let native = claimed.with_native_effect(CredentialNativeEffectDisposition::PossibleEffect);
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::ReadbackVerified,
            Some(version.clone()),
            native.clone(),
        )
        .is_err()
    );
    let readback = native.with_readback(CredentialReadbackDisposition::ExactVersion, digest(4));
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Completed,
            Some(version.clone()),
            readback.clone(),
        )
        .is_err()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Completed,
            Some(version.clone()),
            readback.with_terminal(CredentialTerminalDisposition::Completed),
        )
        .is_ok()
    );
}

#[test]
fn credential_snapshot_rejects_unpaired_and_invalid_terminal_evidence() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let mut unpaired_claim = metadata();
    unpaired_claim.continuation_binding_digest = Some(digest(2));
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Prepared,
            Some(version.clone()),
            unpaired_claim,
        )
        .is_err()
    );
    let mut unpaired_readback = metadata().with_claim(digest(2), digest(3));
    unpaired_readback.readback_observation_digest = Some(digest(4));
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Claimed,
            Some(version.clone()),
            unpaired_readback,
        )
        .is_err()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Failed,
            Some(version.clone()),
            metadata().with_terminal(CredentialTerminalDisposition::FailedWithVerifiedAbsence),
        )
        .is_ok()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Expired,
            Some(version.clone()),
            metadata().with_terminal(CredentialTerminalDisposition::Cancelled),
        )
        .is_err()
    );
    assert!(
        snapshot(
            &provider,
            CredentialOperationState::Tombstoned,
            Some(version),
            metadata()
                .with_terminal(CredentialTerminalDisposition::Tombstoned)
                .with_tombstone(digest(5)),
        )
        .is_err()
    );
}

fn snapshot(
    provider: &ProviderId,
    state: CredentialOperationState,
    version: Option<CredentialVersionRef>,
    metadata: CredentialOperationMetadata,
) -> Result<CredentialOperationSnapshot, CredentialEnrollmentError> {
    CredentialOperationSnapshot::new(
        CredentialOperationId::from_bytes([6; 16]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        state,
        version,
        metadata,
    )
}

fn metadata() -> CredentialOperationMetadata {
    CredentialOperationMetadata::new(
        CommandId::from_bytes([1; 16]),
        IdempotencyKey::new("metadata-shape").unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(1),
        1,
        1,
    )
    .unwrap()
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
