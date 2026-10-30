include!("tests_v2_modules.rs");
use std::thread;
use std::time::Duration;

use runne_application::permission_modes::PermissionMode;
use rusqlite::TransactionBehavior;

use crate::store::permission_modes::model::{
    IssuedNativeModeConfirmationV2, NativeModeConfirmationRequestV2,
    PermissionModeCeremonyStatusV2, PermissionModeStoreError,
};
use binding::{command_and_proof, history};
use support::{Fixture, Storage};

#[test]
fn historical_receipt_readback_survives_expiry_and_workspace_change_denies_commit() {
    let mut fixture = Fixture::new(Storage::File);
    let mut request = fixture.request(PermissionMode::RiskBased, "expiry");
    request.expires_at_unix_ms = Some(unix_ms() + 1500);
    let issued = begin(&fixture, request.clone());
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
    let expiry = request.expires_at_unix_ms.unwrap();
    fixture.change_trust_policy();
    while unix_ms() <= expiry {
        thread::sleep(Duration::from_millis(2));
    }
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
            .commit_confirmed_permission_mode_v2(
                command.clone(),
                proof,
                &fixture.authority_with(Some(&rotated)),
                history(&command),
            )
            .unwrap(),
        receipt
    );
    fixture.reopen();
    assert_eq!(
        fixture
            .store()
            .commit_confirmed_permission_mode_v2(
                command.clone(),
                proof,
                &fixture.authority_with(None),
                history(&command),
            )
            .unwrap(),
        receipt
    );
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

    let mut next = fixture.request(PermissionMode::RiskBased, "workspace-version");
    next.expected_authorization_revision = 1;
    let second = begin(&fixture, next.clone());
    fixture.bump_workspace_version();
    let (command, proof) = command_and_proof(&next, &second);
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::ReauthenticationUnavailable)
    ));
    assert_eq!(fixture.row_phase(&second), (1, 1));
    assert_eq!(fixture.selection_revision(), Some(1));
    assert_eq!(fixture.receipt_count(), 1);
}

#[test]
fn confirmation_at_exact_challenge_deadline_does_not_consume_or_commit() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::AskAlways, "deadline-boundary");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    let deadline = issued.binding().challenge_expires_at_unix_ms;
    let mut writer = fixture.store().inner.writer.lock().unwrap();
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let workspace = super::identity::owned_open_workspace(&tx, &request.scope).unwrap();
    let authority = fixture.authority();
    let managed = super::identity::managed_snapshot(&authority, workspace.project_id).unwrap();
    let closed_rules =
        super::managed_identity::lease::current(&authority, workspace, managed).unwrap();
    let store_identity = super::identity::store_identity(&tx, &request.scope).unwrap();

    assert!(matches!(
        super::ceremony_v2::consume::consume_v2(
            &tx,
            &command,
            proof,
            workspace,
            managed,
            &closed_rules,
            store_identity,
            &fixture.launch,
            deadline,
        ),
        Err(PermissionModeStoreError::ReauthenticationUnavailable)
    ));
    drop(tx);
    drop(writer);

    assert_eq!(fixture.row_phase(&issued), (1, 1));
    assert_eq!(fixture.selection_revision(), None);
    assert_eq!(fixture.receipt_count(), 0);
}

#[test]
fn expired_pending_rows_cancel_and_commit_orders_are_durable() {
    let expiry_fixture = Fixture::new(Storage::Memory);
    let mut expiring = expiry_fixture.request(PermissionMode::AskAlways, "exact-expiry");
    expiring.expires_at_unix_ms = Some(unix_ms() + 500);
    let expired = begin(&expiry_fixture, expiring.clone());
    while unix_ms() <= expiring.expires_at_unix_ms.unwrap() {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        expiry_fixture
            .store()
            .load_permission_mode_confirmation_status_v2(
                &expiring.scope,
                &expiry_fixture.principal,
                expiring.command_id,
            )
            .unwrap(),
        Some(PermissionModeCeremonyStatusV2::Expired)
    );
    assert_eq!(expiry_fixture.row_phase(&expired), (3, 5));

    let mut cancel_fixture = Fixture::new(Storage::File);
    let request = cancel_fixture.request(PermissionMode::RiskBased, "cancel-first");
    let issued = begin(&cancel_fixture, request.clone());
    assert_eq!(
        cancel_fixture
            .store()
            .cancel_permission_mode_confirmation_v2(
                &request.scope,
                &cancel_fixture.principal,
                request.command_id,
            )
            .unwrap(),
        Some(PermissionModeCeremonyStatusV2::Cancelled)
    );
    let (command, proof) = command_and_proof(&request, &issued);
    assert!(
        cancel_fixture
            .store()
            .commit_confirmed_permission_mode_v2(
                command.clone(),
                proof,
                &cancel_fixture.authority(),
                history(&command),
            )
            .is_err()
    );
    cancel_fixture.reopen();
    assert_eq!(cancel_fixture.row_phase(&issued), (3, 4));
    assert_eq!(cancel_fixture.receipt_count(), 0);

    let mut commit_fixture = Fixture::new(Storage::File);
    let request = commit_fixture.request(PermissionMode::RiskBased, "commit-first");
    let issued = begin(&commit_fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    let receipt = commit_fixture
        .store()
        .commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &commit_fixture.authority(),
            history(&command),
        )
        .unwrap();
    let cancelled = commit_fixture
        .store()
        .cancel_permission_mode_confirmation_v2(
            &request.scope,
            &commit_fixture.principal,
            request.command_id,
        )
        .unwrap();
    commit_fixture.reopen();
    assert_eq!(
        cancelled,
        Some(PermissionModeCeremonyStatusV2::Committed(receipt))
    );
    assert_eq!(commit_fixture.row_phase(&issued), (2, 2));
}

#[test]
fn cancel_status_is_readable_in_memory_and_after_file_reopen() {
    for (index, storage) in [Storage::Memory, Storage::File].into_iter().enumerate() {
        let mut fixture = Fixture::new(storage);
        let request = fixture.request(PermissionMode::AskAlways, &format!("cancel-read-{index}"));
        let issued = begin(&fixture, request.clone());
        assert_eq!(
            fixture
                .store()
                .load_permission_mode_confirmation_status_v2(
                    &request.scope,
                    &fixture.principal,
                    request.command_id,
                )
                .unwrap(),
            Some(PermissionModeCeremonyStatusV2::Pending(issued.clone()))
        );
        assert_eq!(
            fixture
                .store()
                .cancel_permission_mode_confirmation_v2(
                    &request.scope,
                    &fixture.principal,
                    request.command_id,
                )
                .unwrap(),
            Some(PermissionModeCeremonyStatusV2::Cancelled)
        );
        if matches!(storage, Storage::File) {
            fixture.reopen();
            assert_eq!(
                fixture
                    .store()
                    .load_permission_mode_confirmation_status_v2(
                        &request.scope,
                        &fixture.principal,
                        request.command_id,
                    )
                    .unwrap(),
                Some(PermissionModeCeremonyStatusV2::Cancelled)
            );
        }
        assert_eq!(fixture.row_phase(&issued), (3, 4));
        assert_eq!(fixture.selection_revision(), None);
        assert_eq!(fixture.receipt_count(), 0);
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn begin(
    fixture: &Fixture,
    request: NativeModeConfirmationRequestV2,
) -> IssuedNativeModeConfirmationV2 {
    match fixture
        .store()
        .begin_permission_mode_confirmation_v2(request, &fixture.authority())
        .unwrap()
    {
        PermissionModeCeremonyStatusV2::Pending(issued) => issued,
        other => panic!("expected pending confirmation, got {other:?}"),
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
