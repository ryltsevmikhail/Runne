use runne_domain::id::{CommandId, IdempotencyKey};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialMigrationMetadata,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialOperationMetadata, CredentialOperationSnapshot, CredentialOperationState,
    CredentialProcessBinding, CredentialReadbackDisposition, CredentialReadinessRevision,
    CredentialTerminalDisposition, WriterIdentityMigrationPhase,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_operation_snapshots_preserve_nullable_allocation_and_replay_metadata() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let metadata = CredentialOperationMetadata::new(
        CommandId::from_bytes([1; 16]),
        IdempotencyKey::new("pair-1").unwrap(),
        owner(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(2),
        10,
        11,
    )
    .unwrap()
    .with_claim(digest(3), digest(4))
    .with_native_effect(CredentialNativeEffectDisposition::PossibleEffect)
    .with_readback(CredentialReadbackDisposition::ExactVersion, digest(5))
    .with_terminal(CredentialTerminalDisposition::Completed)
    .with_tombstone(digest(6));
    let tombstoned = CredentialOperationSnapshot::new(
        CredentialOperationId::from_bytes([7; 16]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialOperationState::Tombstoned,
        Some(version),
        None,
        metadata,
    )
    .unwrap();
    assert_eq!(tombstoned.begin_proof_digest(), digest(2));
    assert_eq!(tombstoned.continuation_binding_digest(), Some(digest(3)));
    assert_eq!(tombstoned.process_release_binding_digest(), Some(digest(4)));
    assert_eq!(tombstoned.tombstone_digest(), Some(digest(6)));
    assert_eq!(
        tombstoned.terminal_disposition(),
        Some(CredentialTerminalDisposition::Completed)
    );

    let revoke = CredentialOperationSnapshot::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Revoke,
        CredentialOperationState::Prepared,
        None,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialOperationMetadata::new(
            CommandId::from_bytes([9; 16]),
            IdempotencyKey::new("revoke-1").unwrap(),
            owner(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            digest(10),
            12,
            12,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(revoke.allocated_credential_version(), None);
}

#[test]
fn credential_lifecycle_snapshot_carries_readiness_revision() {
    let provider = ProviderId::new("openai").unwrap();
    let snapshot = super::super::CredentialLifecycleSnapshot::new(
        provider,
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        7,
    )
    .unwrap();
    assert_eq!(snapshot.readiness_revision().get(), 1);
    assert_eq!(snapshot.next_credential_version(), 7);
}

#[test]
fn credential_writer_migration_snapshot_requires_a_matching_sealed_tuple() {
    let provider = ProviderId::new("openai").unwrap();
    let metadata = CredentialOperationMetadata::new(
        CommandId::from_bytes([12; 16]),
        IdempotencyKey::new("migration-1").unwrap(),
        owner(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(13),
        1,
        1,
    )
    .unwrap();
    assert!(
        CredentialOperationSnapshot::new(
            CredentialOperationId::from_bytes([14; 16]).unwrap(),
            provider.clone(),
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialOperationState::Prepared,
            None,
            None,
            metadata.clone(),
        )
        .is_err()
    );
    assert!(
        CredentialOperationSnapshot::new(
            CredentialOperationId::from_bytes([15; 16]).unwrap(),
            provider,
            CredentialOperationAction::WriterIdentityMigrationEffect,
            CredentialOperationState::Prepared,
            None,
            None,
            metadata.with_migration(migration_metadata()),
        )
        .is_ok()
    );
}

#[test]
fn credential_operation_snapshot_rejects_invalid_action_allocation_and_evidence_shapes() {
    let provider = ProviderId::new("openai").unwrap();
    let metadata = CredentialOperationMetadata::new(
        CommandId::from_bytes([20; 16]),
        IdempotencyKey::new("shape-1").unwrap(),
        owner(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(21),
        1,
        1,
    )
    .unwrap();
    assert!(
        CredentialOperationSnapshot::new(
            CredentialOperationId::from_bytes([22; 16]).unwrap(),
            provider.clone(),
            CredentialOperationAction::Pair,
            CredentialOperationState::Prepared,
            None,
            None,
            metadata.clone(),
        )
        .is_err()
    );
    assert!(
        CredentialOperationSnapshot::new(
            CredentialOperationId::from_bytes([23; 16]).unwrap(),
            provider.clone(),
            CredentialOperationAction::Revoke,
            CredentialOperationState::Prepared,
            Some(CredentialVersionRef::new(provider.clone(), 1).unwrap()),
            None,
            metadata.clone(),
        )
        .is_err()
    );
    assert!(
        CredentialOperationSnapshot::new(
            CredentialOperationId::from_bytes([24; 16]).unwrap(),
            provider.clone(),
            CredentialOperationAction::Revoke,
            CredentialOperationState::Claimed,
            None,
            Some(CredentialVersionRef::new(provider, 1).unwrap()),
            metadata,
        )
        .is_err()
    );
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn owner() -> CredentialInstallationOwnerId {
    CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap()
}

fn migration_metadata() -> CredentialMigrationMetadata {
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let binding = measurements
        .issue_credential_release_migration_binding(
            CredentialOperationId::from_bytes([16; 16]).unwrap(),
            WriterIdentityMigrationPhase::OldWriterEffect,
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            1,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            CredentialProcessBinding::new(
                measurements
                    .writer_process_start_identity([21; 32])
                    .unwrap(),
                measurements
                    .writer_process_handle_identity([22; 32])
                    .unwrap(),
            ),
        )
        .unwrap();
    store.issue_credential_migration_metadata(&binding).unwrap()
}
