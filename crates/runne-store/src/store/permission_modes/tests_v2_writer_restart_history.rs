use std::path::Path;

use runne_application::permission_modes::{PermissionMode, PermissionModeChangeReceipt};
use runne_application::project_trust::{ProjectTrustPersistence, ProjectTrustProjectId};
use rusqlite::OptionalExtension;

use super::super::binding::{command_and_proof, history};
use super::super::support::{Fixture, Storage};
use super::metadata::{self, Checkpoint, Receipt};
use crate::schema;
use crate::store::StoreTransaction;
use crate::store::permission_modes::model::{
    IssuedNativeModeConfirmationV2, NativeModeConfirmationRequestV2, PermissionModeCeremonyStatusV2,
};

pub(super) fn write_and_exit(root: &Path, case: &str) -> ! {
    let fixture = Fixture::new(Storage::File);
    assert_eq!(fixture._root.path().parent().unwrap(), root);
    let request = fixture.request(PermissionMode::RiskBased, case);
    let issued = super::super::begin(&fixture, request.clone());
    assert_eq!(fixture.row_phase(&issued), (1, 1));
    diagnostics(fixture.store(), &request, issued.challenge_id(), (1, 1));
    let receipt = if case == "committed" {
        // Existing Echo verifier is a logical test authority, never Human/native evidence.
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
        assert_eq!(receipt.command_id, request.command_id);
        assert_eq!(receipt.idempotency_key, request.idempotency_key);
        assert_eq!(receipt.intent_digest, command.intent_digest);
        assert_eq!(receipt.projection, history(&command));
        assert_eq!(receipt.selection.scope, request.scope);
        assert_eq!(receipt.selection.selected_mode, request.requested_mode);
        assert_eq!(receipt.selection.preset_version, request.preset_version);
        assert_eq!(receipt.selection.authorization_revision, 1);
        assert_eq!(
            receipt.selection.expires_at_unix_ms,
            request.expires_at_unix_ms
        );
        diagnostics(fixture.store(), &request, issued.challenge_id(), (2, 2));
        Some(canonical_receipt(&receipt))
    } else {
        assert_eq!(case, "pending");
        None
    };
    let public = fixture
        .store()
        .load_permission_mode_confirmation_status_v2(
            &request.scope,
            &fixture.principal,
            request.command_id,
        )
        .unwrap()
        .unwrap();
    match &public {
        PermissionModeCeremonyStatusV2::Pending(value) => assert_eq!(value, &issued),
        PermissionModeCeremonyStatusV2::Committed(value) => {
            assert_eq!(Some(canonical_receipt(value)), receipt);
        }
        _ => panic!("unexpected writer checkpoint status"),
    }
    let project = ProjectTrustProjectId::from_bytes(fixture.project_id.into_bytes());
    let trust = fixture.trust.load(project).unwrap();
    let (authority, lineage) = {
        let connection = fixture.store().inner.writer.lock().unwrap();
        (
            schema::read_authority_id(&connection).unwrap().unwrap(),
            schema::read_event_log_lineage_id(&connection)
                .unwrap()
                .unwrap(),
        )
    };
    let checkpoint = Checkpoint {
        version: 1,
        case: case.into(),
        nested: fixture
            ._root
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
        writer_pid: std::process::id(),
        recovered_pid: None,
        authority,
        lineage: lineage.to_string(),
        project: fixture.project_id.to_string(),
        workspace: request.scope.workspace_id.to_string(),
        principal: fixture.principal.as_str().into(),
        command: request.command_id.to_string(),
        key: request.idempotency_key.as_str().into(),
        mode: "RiskBased".into(),
        preset: 1,
        expected_revision: request.expected_authorization_revision,
        expires: request.expires_at_unix_ms,
        request_digest: *request.public_request_digest().as_bytes(),
        challenge: *issued.challenge_id(),
        binding_digest: *issued.binding().digest().as_bytes(),
        session: *fixture.launch.protected_session_id().unwrap(),
        launch_authority: *fixture.launch.launch_authority_id(),
        desktop_instance: *fixture.launch.desktop_host_instance_id(),
        daemon_instance: *fixture.launch.daemon_instance_id(),
        launch_generation: fixture.launch.launch_generation(),
        key_epoch: fixture.launch.key_epoch(),
        challenge_expires: issued.binding().challenge_expires_at_unix_ms,
        trust_epoch: trust.instance_epoch,
        trust_revision: trust.revision,
        trust_mask: trust.managed_deny_mask,
        trust_status: "Trusted".into(),
        receipt,
    };
    assert_eq!(trust, checkpoint.trust_record());
    assert_issued(&issued, &request, &checkpoint);
    checkpoint.daemon(root);
    metadata::write(root, "checkpoint.json", &checkpoint);
    // Fixture, both Store connections, trust connection and lease remain owned here.
    // No return, checkpoint, explicit close or destructor precedes this completed-stage cut.
    std::process::abort()
}

pub(super) fn canonical_receipt(value: &PermissionModeChangeReceipt) -> Receipt {
    Receipt {
        command: value.command_id.to_string(),
        key: value.idempotency_key.as_str().into(),
        intent: *value.intent_digest.as_bytes(),
        authority: value.selection.scope.runtime_authority_id.0.clone(),
        principal: value.selection.scope.principal_id.as_str().into(),
        workspace: value.selection.scope.workspace_id.to_string(),
        mode: match value.selection.selected_mode {
            PermissionMode::AskAlways => "AskAlways",
            PermissionMode::RiskBased => "RiskBased",
            PermissionMode::FullAccess => "FullAccess",
        }
        .into(),
        preset: value.selection.preset_version.as_u16(),
        revision: value.selection.authorization_revision,
        expires: value.selection.expires_at_unix_ms,
        history: crate::store::permission_modes::receipt_codec::encode_history(&value.projection)
            .unwrap(),
    }
}

pub(super) fn assert_issued(
    issued: &IssuedNativeModeConfirmationV2,
    request: &NativeModeConfirmationRequestV2,
    saved: &Checkpoint,
) {
    let binding = issued.binding();
    assert_eq!(issued.challenge_id(), &saved.challenge);
    assert_eq!(binding.command_id, request.command_id);
    assert_eq!(binding.idempotency_key, request.idempotency_key);
    assert_eq!(binding.scope, request.scope);
    assert_eq!(
        binding.expected_authorization_revision,
        request.expected_authorization_revision
    );
    assert_eq!(binding.requested_mode, request.requested_mode);
    assert_eq!(binding.preset_version, request.preset_version);
    assert_eq!(binding.expires_at_unix_ms, request.expires_at_unix_ms);
    assert_eq!(
        binding.public_request_digest,
        request.public_request_digest()
    );
    assert_eq!(binding.digest().as_bytes(), &saved.binding_digest);
    assert_eq!(binding.protected_session_id, saved.session);
    assert_eq!(
        binding.challenge_expires_at_unix_ms,
        saved.challenge_expires
    );
    assert!(
        super::super::unix_ms() < saved.challenge_expires,
        "challenge expired"
    );
}

pub(super) fn diagnostics(
    store: &StoreTransaction,
    request: &NativeModeConfirmationRequestV2,
    challenge: &[u8],
    expected_phase: (i64, i64),
) {
    let committed = expected_phase == (2, 2);
    let connection = store.inner.writer.lock().unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM permission_mode_command_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let revision: Option<i64> = connection
        .query_row(
            "SELECT authorization_revision FROM permission_mode_selections WHERE workspace_id=?1",
            [request.scope.workspace_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    let phase: (i64, i64) = connection.query_row(
        "SELECT state,confirmation_phase FROM permission_mode_native_challenges WHERE challenge_id=?1",
        [challenge], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(count, i64::from(committed));
    assert_eq!(revision, committed.then_some(1));
    assert_eq!(phase, expected_phase);
}
