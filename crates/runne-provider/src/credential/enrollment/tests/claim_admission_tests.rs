use super::super::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialMeasurementSnapshot,
    CredentialOperationAction, CredentialOperationId, CredentialOperationMetadata,
    CredentialOperationSnapshot, CredentialOperationState, CredentialTicketAttempt,
    IssuedCredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn sealed_claim_admission_rejects_forged_process_release_digest() {
    let (_, authority) = CredentialEnrollmentAuthorityPair::new().split();
    let draft = claim(1, measured(17));

    assert_eq!(
        authority.seal_claim_operation(snapshot(&authority, 1), draft),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn store_authority_rejects_unsealed_claims() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();

    assert_eq!(
        store.validate_claim_operation(&claim(1, canonical_digest())),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn claim_admission_rejects_foreign_measurement_and_store_authorities() {
    let (store, authority) = CredentialEnrollmentAuthorityPair::new().split();
    let (foreign_store, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let foreign_snapshot = snapshot(&foreign_measurements, 1);
    let foreign_claim = foreign_measurements
        .seal_claim_operation(foreign_snapshot.clone(), claim(1, canonical_digest()))
        .unwrap();

    assert_eq!(
        authority.seal_claim_operation(foreign_snapshot, claim(1, canonical_digest())),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
    assert_eq!(
        store.validate_claim_operation(&foreign_claim),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
    assert_eq!(
        foreign_store.validate_claim_operation(&foreign_claim),
        Ok(canonical_digest())
    );
}

#[test]
fn versionless_actions_can_be_measured_sealed_and_store_validated() {
    for action in [
        CredentialOperationAction::LegacySourceCleanup,
        CredentialOperationAction::WriterIdentityMigrationEffect,
        CredentialOperationAction::WriterIdentityMigrationVerify,
    ] {
        let (store, authority) = CredentialEnrollmentAuthorityPair::new().split();
        let measurements = snapshot(&authority, 1);
        let draft = claim_for_action(action, measured(17));
        let digest = authority
            .measure_claim_operation(&measurements, &draft)
            .unwrap();
        let draft = draft.bind_process_release_digest(digest).unwrap();
        let sealed = authority.seal_claim_operation(measurements, draft).unwrap();

        assert_eq!(store.validate_claim_operation(&sealed), Ok(digest));
    }
}

fn snapshot(
    authority: &CredentialEnrollmentMeasurementAuthority,
    supervisor_generation: u64,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([1; 32]).unwrap(),
        authority.release_manifest_digest([2; 32]).unwrap(),
        authority.desktop_executable_identity([3; 32]).unwrap(),
        authority.writer_executable_identity([4; 32]).unwrap(),
        authority.reader_executable_identity([5; 32]).unwrap(),
        authority.contract_bundle_digest([6; 32]).unwrap(),
        authority.daemon_authority_id([7; 32]).unwrap(),
        authority.protected_session_id([8; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(supervisor_generation)
            .unwrap(),
        authority.writer_launch_id([9; 32]).unwrap(),
        authority.writer_process_start_identity([10; 32]).unwrap(),
        authority.writer_process_handle_identity([11; 32]).unwrap(),
        authority.broker_channel_binding([12; 32]).unwrap(),
        authority.continuation_binding_digest([13; 32]).unwrap(),
    )
    .unwrap()
}

fn claim(
    supervisor_generation: u64,
    process_release_binding_digest: CredentialBindingDigest,
) -> ClaimCredentialOperation {
    claim_for_action_with_supervisor(
        CredentialOperationAction::Pair,
        supervisor_generation,
        process_release_binding_digest,
    )
}

fn claim_for_action(
    action: CredentialOperationAction,
    process_release_binding_digest: CredentialBindingDigest,
) -> ClaimCredentialOperation {
    claim_for_action_with_supervisor(action, 1, process_release_binding_digest)
}

fn claim_for_action_with_supervisor(
    action: CredentialOperationAction,
    supervisor_generation: u64,
    process_release_binding_digest: CredentialBindingDigest,
) -> ClaimCredentialOperation {
    let snapshot_action = match action {
        CredentialOperationAction::WriterIdentityMigrationEffect
        | CredentialOperationAction::WriterIdentityMigrationVerify => {
            CredentialOperationAction::LegacySourceCleanup
        }
        other => other,
    };
    let version = (snapshot_action == CredentialOperationAction::Pair)
        .then(|| CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap());
    ClaimCredentialOperation::new(
        receipt(snapshot_action, version),
        measured(15),
        measured(13),
        process_release_binding_digest,
        1,
        supervisor_generation,
    )
    .unwrap()
}

fn receipt(
    action: CredentialOperationAction,
    version: Option<CredentialVersionRef>,
) -> IssuedCredentialTicketAttempt {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let operation = CredentialOperationId::from_bytes([14; 16]).unwrap();
    let snapshot = CredentialOperationSnapshot::new(
        operation,
        ProviderId::new("openai").unwrap(),
        action,
        CredentialOperationState::Prepared,
        version,
        None,
        CredentialOperationMetadata::new(
            runne_domain::id::CommandId::from_bytes([14; 16]),
            runne_domain::id::IdempotencyKey::new("claim-admission").unwrap(),
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            measured(16),
            1,
            1,
        )
        .unwrap(),
    )
    .unwrap();
    store
        .hydrate_issued_credential_ticket_attempt(
            snapshot,
            CredentialTicketAttempt::new(1).unwrap(),
            1,
            2,
        )
        .unwrap()
}

fn canonical_digest() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([
        0x51, 0x27, 0xa0, 0xaf, 0xf8, 0x77, 0xdf, 0xe3, 0x6e, 0xd7, 0x86, 0x09, 0xb5, 0x88, 0x27,
        0x22, 0xc6, 0xa1, 0xce, 0xc4, 0x64, 0xb9, 0x1f, 0xe8, 0xc0, 0x9f, 0x88, 0x77, 0xa1, 0xa3,
        0x68, 0xa1,
    ])
    .unwrap()
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
