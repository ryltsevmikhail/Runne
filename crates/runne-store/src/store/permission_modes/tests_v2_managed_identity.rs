use runne_application::permission_modes::{PermissionMode, PermissionModeError};
use runne_application::project_trust::ProjectTrustPersistence;

use super::begin;
use super::binding::{command_and_proof, history};
use super::support::{Fixture, Storage};
use crate::store::permission_modes::model::{
    ManagedIdentityMetadata, PermissionModeCeremonyStatusV2, PermissionModeStoreError,
};

#[path = "tests_v2_managed_identity_golden.rs"]
mod golden;
#[path = "tests_v2_managed_identity_history.rs"]
mod history;
#[path = "tests_v2_managed_identity_lease.rs"]
mod lease;
#[path = "tests_v2_managed_identity_tamper.rs"]
mod tamper;

#[test]
fn issued_v2_uses_canonical_rules_and_envelope_and_replays_exact_metadata() {
    let mut fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "identity-replay");
    let issued = begin(&fixture, request.clone());
    let identity = issued.managed_identity();
    assert!(identity.project_version > 0);
    assert_eq!(
        issued.binding().managed_policy_digest,
        identity.canonical_digest
    );
    assert_eq!(
        identity.challenge_binding.as_ref().unwrap().envelope_digest,
        issued.binding().challenge_binding_digest
    );
    let duplicate = fixture
        .store()
        .begin_permission_mode_confirmation_v2(request.clone(), &fixture.authority())
        .unwrap();
    assert_eq!(
        duplicate,
        PermissionModeCeremonyStatusV2::Pending(issued.clone())
    );

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
    let record_digest = runne_application::permission_modes::managed_policy_semantics_digest(
        runne_application::project_trust::ProjectTrustProjectId::from_bytes(identity.project_id),
        identity.snapshot.record,
    );
    let writer = fixture.store().inner.writer.lock().unwrap();
    let stored_selection: Vec<u8> = writer
        .query_row(
            "SELECT managed_policy_digest FROM permission_mode_selections WHERE workspace_id=?1",
            [request.scope.workspace_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let stored_receipt: Vec<u8> = writer
        .query_row(
            "SELECT managed_policy_digest FROM permission_mode_command_receipts WHERE command_id=?1",
            [request.command_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_selection.as_slice(), record_digest.as_bytes());
    assert_eq!(stored_receipt.as_slice(), record_digest.as_bytes());
    assert_ne!(
        stored_selection.as_slice(),
        identity.canonical_digest.as_bytes()
    );
    drop(writer);
    fixture.reopen();
    let selected = fixture
        .store()
        .load_permission_mode_selection_with_managed_identity(
            &request.scope,
            &fixture.principal,
            &fixture.authority(),
        )
        .unwrap();
    assert_eq!(selected.selection.selected_mode, PermissionMode::RiskBased);
    assert!(matches!(
        selected.identity,
        ManagedIdentityMetadata::ClosedRulesV2(ref value)
            if value == identity
    ));
}

#[test]
fn absent_selection_uses_actual_held_rules_snapshot() {
    let fixture = Fixture::new(Storage::File);
    let authority = fixture.authority();
    let expected = authority.trust_lease.snapshot().unwrap();
    let selected = fixture
        .store()
        .load_permission_mode_selection_with_managed_identity(
            &fixture.scope,
            &fixture.principal,
            &authority,
        )
        .unwrap();
    assert_eq!(selected.selection.selected_mode, PermissionMode::AskAlways);
    assert_eq!(selected.selection.authorization_revision, 0);
    assert!(matches!(
        selected.identity,
        ManagedIdentityMetadata::ClosedRulesV2(ref value)
            if value.snapshot == expected && value.project_version > 0
    ));
}

#[test]
fn project_version_change_rejects_consume_without_fallback() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "project-version");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture
        .store()
        .inner
        .writer
        .lock()
        .unwrap()
        .execute(
            "UPDATE projects SET version=version+1 WHERE project_id=?1",
            [fixture.project_id.into_bytes().as_slice()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::ManagedPolicyStale)
            | Err(PermissionModeStoreError::ReauthenticationUnavailable)
            | Err(PermissionModeStoreError::Command(
                PermissionModeError::StaleRevision
            ))
    ));
    assert_eq!(fixture.row_phase(&issued), (1, 1));
    assert_eq!(fixture.selection_revision(), None);
    assert_eq!(fixture.receipt_count(), 0);
}

#[test]
fn altered_issued_metadata_is_corrupt_and_never_reinterpreted_as_legacy() {
    let fixture = Fixture::new(Storage::Memory);
    let request = fixture.request(PermissionMode::RiskBased, "missing-extension");
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
                 SET canonical_digest=zeroblob(32) WHERE challenge_id=?1",
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
fn six_rule_change_after_issue_rejects_commit() {
    let mut fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "rules-change");
    let issued = begin(&fixture, request.clone());
    let (command, proof) = command_and_proof(&request, &issued);
    fixture.trust_lease.take();
    let path = fixture
        ._root
        .path()
        .join("runtime/daemon/trust-anchor.sqlite.project-trust");
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE managed_effect_policies SET network_use=1 WHERE project_id=?1",
            [fixture.project_id.into_bytes().as_slice()],
        )
        .unwrap();
    fixture.trust_lease = Some(
        fixture
            .trust
            .acquire_effect_lease(
                runne_application::project_trust::ProjectTrustProjectId::from_bytes(
                    fixture.project_id.into_bytes(),
                ),
            )
            .unwrap(),
    );
    assert!(matches!(
        fixture.store().commit_confirmed_permission_mode_v2(
            command.clone(),
            proof,
            &fixture.authority(),
            history(&command),
        ),
        Err(PermissionModeStoreError::ManagedPolicyStale)
            | Err(PermissionModeStoreError::ReauthenticationUnavailable)
    ));
    assert_eq!(fixture.row_phase(&issued), (1, 1));
    assert_eq!(fixture.selection_revision(), None);
    assert_eq!(fixture.receipt_count(), 0);
}
