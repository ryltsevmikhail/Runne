use std::sync::{Arc, Barrier};
use std::thread;

use runne_application::permission_modes::{PermissionMode, PermissionModeError};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};

use super::begin;
use super::binding::{command_and_proof, history};
use super::support::{Fixture, Storage};
use crate::store::permission_modes::model::{
    PermissionModeCeremonyStatusV2, PermissionModeStoreError,
};

#[test]
fn all_modes_use_store_lifecycle_in_memory_and_file_stores() {
    for storage in [Storage::Memory, Storage::File] {
        let mut fixture = Fixture::new(storage);
        let modes = [
            PermissionMode::AskAlways,
            PermissionMode::RiskBased,
            PermissionMode::FullAccess,
        ];
        let mut last_command = None;
        for (index, mode) in modes.into_iter().enumerate() {
            let mut request = fixture.request(mode, &format!("all-modes-{index}"));
            request.expected_authorization_revision = index as u64;
            let issued = begin(&fixture, request.clone());
            let duplicate = fixture
                .store()
                .begin_permission_mode_confirmation_v2(request.clone(), &fixture.authority())
                .unwrap();
            assert_eq!(
                duplicate,
                PermissionModeCeremonyStatusV2::Pending(issued.clone())
            );
            let (command, proof) = command_and_proof(&request, &issued);
            let receipt = fixture
                .store()
                .commit_confirmed_permission_mode_v2(
                    command.clone(),
                    proof,
                    &fixture.authority(),
                    history(&command),
                )
                .unwrap();
            assert_eq!(receipt.selection.authorization_revision, index as u64 + 1);
            assert_eq!(fixture.selection_revision(), Some(index as i64 + 1));
            assert_eq!(fixture.receipt_count(), index as i64 + 1);
            assert_eq!(fixture.row_phase(&issued), (2, 2));

            let old_authority = fixture.authority_with(None);
            let replay = fixture
                .store()
                .commit_confirmed_permission_mode_v2(
                    command.clone(),
                    proof,
                    &old_authority,
                    history(&command),
                )
                .unwrap();
            assert_eq!(replay, receipt);
            assert_eq!(fixture.receipt_count(), index as i64 + 1);
            last_command = Some((request, receipt));
        }
        if matches!(storage, Storage::File) {
            fixture.reopen();
        }
        let (request, receipt) = last_command.unwrap();
        assert_eq!(
            fixture
                .store()
                .load_permission_mode_confirmation_status_v2(
                    &request.scope,
                    &fixture.principal,
                    request.command_id,
                )
                .unwrap(),
            Some(PermissionModeCeremonyStatusV2::Committed(receipt))
        );
        assert_eq!(fixture.selection_revision(), Some(3));
        assert_eq!(fixture.receipt_count(), 3);
    }
}

#[test]
fn consume_rejects_same_launch_with_a_rotated_session() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "consume-session-rotation");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    let rotated = fixture
        .launch
        .with_protected_session_id([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x52,
        ])
        .unwrap();
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority_with(Some(&rotated)),
            history(&command),
        ),
        Err(PermissionModeStoreError::ReauthenticationUnavailable)
    ));
    assert_eq!(fixture.row_phase(&issued), (3, 3));
    assert_eq!(fixture.selection_revision(), None);
    assert_eq!(fixture.receipt_count(), 0);
}

#[test]
fn session_rotation_invalidates_pending_and_full_access_requires_both_proofs() {
    let mut fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::FullAccess, "session-rotation");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture.reopen();
    let rotated = fixture
        .launch
        .with_protected_session_id([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x52,
        ])
        .unwrap();
    assert_eq!(
        fixture
            .store()
            .begin_permission_mode_confirmation_v2(
                request.clone(),
                &fixture.authority_with(Some(&rotated)),
            )
            .unwrap(),
        PermissionModeCeremonyStatusV2::Invalidated
    );
    assert_eq!(fixture.row_phase(&issued), (3, 3));
    assert_eq!(
        fixture
            .store()
            .cancel_permission_mode_confirmation_v2(
                &request.scope,
                &fixture.principal,
                request.command_id,
            )
            .unwrap(),
        Some(PermissionModeCeremonyStatusV2::Invalidated)
    );
    assert!(
        fixture
            .store()
            .commit_confirmed_permission_mode_v2(
                command.clone(),
                proof,
                &fixture.authority_with(Some(&rotated)),
                history(&command),
            )
            .is_err()
    );

    let full_fixture = Fixture::new(Storage::Memory);
    let first = full_fixture.request(PermissionMode::FullAccess, "full-access-one");
    let issued_one = begin(&full_fixture, first.clone());
    let (mut command_one, proof_one) = command_and_proof(&first, &issued_one);
    command_one.verified_native_challenge = None;
    assert!(matches!(
        full_fixture.store().commit_confirmed_permission_mode_v2(
            command_one,
            proof_one,
            &full_fixture.authority(),
            history(&command_and_proof(&first, &issued_one).0),
        ),
        Err(PermissionModeStoreError::Command(
            PermissionModeError::ReauthenticationRequired
        ))
    ));
    let second = full_fixture.request(PermissionMode::FullAccess, "full-access-two");
    let issued_two = begin(&full_fixture, second);
    let (command_one, _) = command_and_proof(&first, &issued_one);
    let wrong_v2 = super::binding::verified_v2(&issued_two);
    assert!(
        full_fixture
            .store()
            .commit_confirmed_permission_mode_v2(
                command_one.clone(),
                wrong_v2,
                &full_fixture.authority(),
                history(&command_one),
            )
            .is_err()
    );
}

#[test]
fn receipt_insert_failure_rolls_back_consumption_selection_and_history() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "rollback");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture.abort_receipt_inserts(true);
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::Unavailable)
    ));
    fixture.abort_receipt_inserts(false);
    assert_eq!(fixture.row_phase(&issued), (1, 1));
    assert_eq!(fixture.selection_revision(), None);
    assert_eq!(fixture.receipt_count(), 0);
    assert_eq!(
        fixture
            .store()
            .begin_permission_mode_confirmation_v2(request, &fixture.authority(),)
            .unwrap(),
        PermissionModeCeremonyStatusV2::Pending(issued)
    );
}

#[test]
fn concurrent_cancel_and_commit_have_one_durable_file_backed_winner() {
    let mut fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "concurrent-terminal");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    let store = fixture.store().clone();
    let cancel_store = store.clone();
    let scope = request.scope.clone();
    let principal = fixture.principal.clone();
    let commit_principal = principal.clone();
    let trust = fixture.trust.clone();
    let trust_project = ProjectTrustProjectId::from_bytes(fixture.project_id.into_bytes());
    let launch = fixture.launch;
    let gate = Arc::new(Barrier::new(3));
    let commit_gate = Arc::clone(&gate);
    let commit = thread::spawn(move || {
        commit_gate.wait();
        let lease = trust.acquire_effect_lease(trust_project).unwrap();
        let authority = crate::store::permission_modes::model::PermissionModeAuthorityContext::new(
            &commit_principal,
            trust_project,
            lease.as_ref(),
            Some(&launch),
        );
        store.commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &authority,
            history(&command),
        )
    });
    let cancel_gate = Arc::clone(&gate);
    let cancel = thread::spawn(move || {
        cancel_gate.wait();
        cancel_store.cancel_permission_mode_confirmation_v2(&scope, &principal, request.command_id)
    });
    fixture.trust_lease.take();
    gate.wait();
    let commit = commit.join().unwrap();
    let cancel = cancel.join().unwrap().unwrap().unwrap();
    let terminal = fixture.row_phase(&issued);
    match terminal {
        (2, 2) => {
            let receipt = commit.unwrap();
            assert_eq!(cancel, PermissionModeCeremonyStatusV2::Committed(receipt));
            assert_eq!(fixture.selection_revision(), Some(1));
            assert_eq!(fixture.receipt_count(), 1);
        }
        (3, 4) => {
            assert!(commit.is_err());
            assert_eq!(cancel, PermissionModeCeremonyStatusV2::Cancelled);
            assert_eq!(fixture.selection_revision(), None);
            assert_eq!(fixture.receipt_count(), 0);
        }
        terminal => panic!("unexpected terminal state {terminal:?}"),
    }
    fixture.reopen();
    assert_eq!(fixture.row_phase(&issued), terminal);
}
