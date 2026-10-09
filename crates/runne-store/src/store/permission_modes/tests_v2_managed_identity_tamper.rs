use runne_application::permission_modes::PermissionMode;

use super::{Fixture, Storage, begin, command_and_proof, history};
use crate::store::permission_modes::model::PermissionModeStoreError;

#[test]
fn missing_pending_identity_is_corrupt_instead_of_legacy() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "missing-challenge-identity");
    let issued = begin(&fixture, request.clone());
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_native_challenge_managed_identity_no_delete",
            )
            .unwrap();
        writer
            .execute(
                "DELETE FROM permission_mode_native_challenge_managed_identity
                 WHERE challenge_id=?1",
                [issued.challenge_id().as_slice()],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().load_permission_mode_confirmation_status_v2(
            &request.scope,
            &fixture.principal,
            request.command_id,
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

#[test]
fn unknown_identity_encoding_tag_is_corrupt() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "unknown-identity-tag");
    let issued = begin(&fixture, request.clone());
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_native_challenge_managed_identity_immutable;
                 PRAGMA ignore_check_constraints=ON;",
            )
            .unwrap();
        writer
            .execute(
                "UPDATE permission_mode_native_challenge_managed_identity
                 SET encoding_tag=99 WHERE challenge_id=?1",
                [issued.challenge_id().as_slice()],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().load_permission_mode_confirmation_status_v2(
            &request.scope,
            &fixture.principal,
            request.command_id,
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

#[test]
fn challenge_metadata_cannot_be_substituted_across_projects() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "challenge-project-substitution");
    let issued = begin(&fixture, request.clone());
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_native_challenge_managed_identity_immutable",
            )
            .unwrap();
        writer
            .execute(
                "UPDATE permission_mode_native_challenge_managed_identity
                 SET project_id=zeroblob(16) WHERE challenge_id=?1",
                [issued.challenge_id().as_slice()],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().load_permission_mode_confirmation_status_v2(
            &request.scope,
            &fixture.principal,
            request.command_id,
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

#[test]
fn receipt_identity_cannot_be_relinked_to_another_challenge() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "receipt-challenge-link");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture
        .store()
        .commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        )
        .unwrap();

    let mut next = fixture.request(PermissionMode::RiskBased, "second-challenge-link");
    next.expected_authorization_revision = 1;
    let second = begin(&fixture, next);
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_command_receipt_managed_identity_immutable",
            )
            .unwrap();
        writer
            .execute(
                "UPDATE permission_mode_command_receipt_managed_identity
                 SET challenge_id=?1 WHERE command_id=?2",
                [
                    second.challenge_id().as_slice(),
                    request.command_id.as_bytes().as_slice(),
                ],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

#[test]
fn missing_receipt_identity_is_corrupt_on_duplicate_readback() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "missing-receipt-identity");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture
        .store()
        .commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        )
        .unwrap();
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_command_receipt_managed_identity_no_delete",
            )
            .unwrap();
        writer
            .execute(
                "DELETE FROM permission_mode_command_receipt_managed_identity
                 WHERE command_id=?1",
                [request.command_id.as_bytes().as_slice()],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}

#[test]
fn unknown_receipt_encoding_tag_is_corrupt_on_duplicate_readback() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "unknown-receipt-tag");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture
        .store()
        .commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        )
        .unwrap();
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        writer
            .execute_batch(
                "DROP TRIGGER permission_mode_command_receipt_managed_identity_immutable;
                 PRAGMA ignore_check_constraints=ON;",
            )
            .unwrap();
        writer
            .execute(
                "UPDATE permission_mode_command_receipt_managed_identity
                 SET encoding_tag=99 WHERE command_id=?1",
                [request.command_id.as_bytes().as_slice()],
            )
            .unwrap();
    }
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::CorruptData)
    ));
}
