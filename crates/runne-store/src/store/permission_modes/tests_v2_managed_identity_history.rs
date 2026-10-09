use runne_application::permission_modes::{
    EffectiveModeHistoryState, NotReadyReason, PermissionMode, PermissionModeHistoryProjection,
    PresetVersion, SetPermissionModeCommand,
};
use runne_application::project_trust::ProjectTrustProjectId;
use runne_domain::id::{IdempotencyKey, IntegrityDigest};

use super::super::begin;
use super::super::binding::{command_and_proof, history};
use super::super::support::{Fixture, Storage};
use crate::store::permission_modes::model::{ManagedIdentityMetadata, PermissionModeStoreError};

fn assert_trigger_error(result: rusqlite::Result<usize>, message: &str) {
    let error = result.expect_err("V67 metadata trigger must reject the write");
    assert!(error.to_string().contains(message), "{error}");
}

#[test]
fn legacy_selection_without_extension_stays_explicit_v1() {
    let fixture = Fixture::new(Storage::File);
    let authority = fixture.authority();
    let managed = crate::store::permission_modes::identity::managed_snapshot(
        &authority,
        fixture.project_id.into_bytes(),
    )
    .unwrap();
    let mut command = SetPermissionModeCommand {
        command_id: runne_domain::id::CommandId::from_bytes(uuid::Uuid::now_v7().into_bytes()),
        scope: fixture.scope.clone(),
        expected_authorization_revision: 0,
        requested_mode: PermissionMode::RiskBased,
        preset_version: PresetVersion::V1,
        intent_digest: IntegrityDigest::from_bytes([0; 32]),
        idempotency_key: IdempotencyKey::new("legacy-managed-identity").unwrap(),
        expires_at_unix_ms: None,
        managed_policy_version: managed.revision,
        managed_policy_digest: managed.digest,
        challenge_binding_digest: None,
        challenge_expires_at_unix_ms: None,
        verified_native_challenge: None,
    };
    command.intent_digest = command.computed_intent_digest();
    let history = PermissionModeHistoryProjection {
        selected_mode: command.requested_mode,
        effective: EffectiveModeHistoryState::NotReady(NotReadyReason::NativeContainment),
        authorization_revision: 1,
        preset_version: command.preset_version,
        managed_policy_version: command.managed_policy_version,
        containment: None,
        network_state: runne_application::permission_modes::NetworkState::Unavailable,
        expires_at_unix_ms: None,
    };
    fixture
        .store()
        .commit_permission_mode_change(command, &authority, history)
        .unwrap();
    let selected = fixture
        .store()
        .load_permission_mode_selection_with_managed_identity(
            &fixture.scope,
            &fixture.principal,
            &authority,
        )
        .unwrap();
    assert!(matches!(
        selected.identity,
        ManagedIdentityMetadata::LegacyRecordV1(ref value)
            if value.managed_policy_digest == managed.digest
    ));
}

#[test]
fn committed_duplicate_readback_rejects_receipt_metadata_tampering() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "tampered-receipt-readback");
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
                "DROP TRIGGER permission_mode_command_receipt_managed_identity_immutable",
            )
            .unwrap();
        writer
            .execute(
                "UPDATE permission_mode_command_receipt_managed_identity
                 SET canonical_digest=zeroblob(32) WHERE command_id=?1",
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
fn v67_metadata_insert_update_and_delete_guards_are_active() {
    let fixture = Fixture::new(Storage::File);
    let request = fixture.request(PermissionMode::RiskBased, "metadata-guards");
    let issued = begin(&fixture, request.clone());
    let challenge_id = issued.challenge_id();
    {
        let writer = fixture.store().inner.writer.lock().unwrap();
        assert_trigger_error(
            writer.execute(
                "INSERT INTO permission_mode_native_challenge_managed_identity
                 SELECT ?1,encoding_tag,project_id,project_version,record_instance_epoch,
                        record_revision,record_status,record_deny_mask,policy_version,
                        fs_read_decision,fs_create_decision,fs_write_decision,fs_delete_decision,
                        process_start_decision,network_use_decision,frozen_policy_version,
                        local_command_policy_version,legacy_issued_digest,canonical_digest,
                        envelope_digest
                 FROM permission_mode_native_challenge_managed_identity WHERE challenge_id=?2",
                [[0xee; 16].as_slice(), challenge_id.as_slice()],
            ),
            "managed identity does not match issued challenge",
        );
        assert_trigger_error(
            writer.execute(
                "UPDATE permission_mode_native_challenge_managed_identity
                 SET canonical_digest=zeroblob(32) WHERE challenge_id=?1",
                [challenge_id.as_slice()],
            ),
            "issued managed identity is immutable",
        );
        assert_trigger_error(
            writer.execute(
                "DELETE FROM permission_mode_native_challenge_managed_identity
                 WHERE challenge_id=?1",
                [challenge_id.as_slice()],
            ),
            "issued managed identity is retained",
        );
    }

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
    let writer = fixture.store().inner.writer.lock().unwrap();
    assert_trigger_error(
        writer.execute(
            "INSERT INTO permission_mode_command_receipt_managed_identity
             SELECT ?1,challenge_id,authorization_revision,encoding_tag,project_version,
                    canonical_digest,envelope_digest
             FROM permission_mode_command_receipt_managed_identity WHERE command_id=?2",
            [
                [0xef; 16].as_slice(),
                request.command_id.as_bytes().as_slice(),
            ],
        ),
        "receipt managed identity does not match committed command",
    );
    assert_trigger_error(
        writer.execute(
            "UPDATE permission_mode_command_receipt_managed_identity
             SET canonical_digest=zeroblob(32) WHERE command_id=?1",
            [request.command_id.as_bytes().as_slice()],
        ),
        "receipt managed identity is immutable",
    );
    assert_trigger_error(
        writer.execute(
            "DELETE FROM permission_mode_command_receipt_managed_identity
             WHERE command_id=?1",
            [request.command_id.as_bytes().as_slice()],
        ),
        "receipt managed identity is retained",
    );
}

#[test]
fn legacy_record_digest_v1_golden_remains_byte_exact() {
    let digest = runne_application::permission_modes::managed_policy_semantics_digest(
        ProjectTrustProjectId::from_bytes([0x44; 16]),
        runne_application::project_trust::ProjectTrustRecord {
            status: runne_application::project_trust::ProjectTrustStatus::Trusted,
            instance_epoch: 7,
            revision: 3,
            managed_deny_mask: 5,
        },
    );
    assert_eq!(
        super::super::hex(digest.as_bytes()),
        "66fd57fa707f18f6c607771983a09d3e3fefbe49f5ff57a7df2d1141c3f498d4"
    );
}
