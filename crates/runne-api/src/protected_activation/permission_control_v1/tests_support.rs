use super::*;

pub fn uuid(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = (value[6] & 0x0f) | 0x70;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}

pub fn context(phase: PermissionControlPhaseV1) -> PermissionControlContextV1 {
    PermissionControlContextV1 {
        runtime_authority: "runtime-local".into(),
        store_lineage_id: uuid(1),
        stable_subject_digest: [2; 32],
        protected_launch_authority_id: uuid(3),
        desktop_authority_id: uuid(4),
        daemon_instance_id: uuid(5),
        protected_session_id: uuid(6),
        launch_generation: 7,
        native_key_epoch: 8,
        command_id: uuid(9),
        idempotency_key: "mode-change-9".into(),
        public_request_digest: [10; 32],
        predecessor_transcript_digest: if phase == PermissionControlPhaseV1::Request {
            [0; 32]
        } else {
            [11; 32]
        },
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    }
}

pub fn mode_challenge() -> PermissionControlModeChallengeV1 {
    PermissionControlModeChallengeV1 {
        principal: "local-user".into(),
        workspace_id: uuid(12),
        workspace_label: "Example workspace".into(),
        expected_authorization_revision: 4,
        requested_mode: PermissionModeSelectionV1::FullAccess,
        preset_version: 1,
        mode_expires_at_unix_ms: Some(3_000),
        managed_policy_revision: 5,
        managed_policy_digest: [13; 32],
        issued_challenge_binding_digest: [14; 32],
        ceremony_expires_at_unix_ms: 2_000,
        native_warning_version: 1,
        challenge_id: [15; 16],
        nonce: [16; 32],
    }
}

pub fn managed_policy() -> ManagedPolicyV1 {
    ManagedPolicyV1 {
        fs_read: ManagedDecisionV1::Allow,
        fs_create: ManagedDecisionV1::Ask,
        fs_write: ManagedDecisionV1::Deny,
        fs_delete: ManagedDecisionV1::Allow,
        process_start: ManagedDecisionV1::Ask,
        network_use: ManagedDecisionV1::Deny,
    }
}

pub fn managed_challenge() -> PermissionControlManagedChallengeV1 {
    PermissionControlManagedChallengeV1 {
        registered_administrator_digest: [17; 32],
        registration_generation: 3,
        project_id: uuid(18),
        project_label: "Project Alpha".into(),
        expected_t1_epoch: 5,
        expected_t1_revision: 9,
        current_policy: managed_policy(),
        requested_policy: ManagedPolicyV1 {
            fs_read: ManagedDecisionV1::Deny,
            ..managed_policy()
        },
        current_policy_digest: [19; 32],
        requested_policy_digest: [20; 32],
        managed_schema_version: 1,
        source_schema_version: 2,
        local_command_schema_version: 1,
        issued_challenge_binding_digest: [21; 32],
        ceremony_expires_at_unix_ms: 2_000,
        native_warning_version: 1,
        challenge_id: [22; 16],
        nonce: [23; 32],
    }
}

pub fn result(context: &PermissionControlContextV1) -> PermissionControlResultV1 {
    PermissionControlResultV1 {
        code: PermissionControlResultCodeV1::Committed,
        command_id: context.command_id,
        public_request_digest: context.public_request_digest,
        receipt_digest: Some([24; 32]),
        authorization_revision: Some(6),
        managed_policy_revision: Some(9),
    }
}

pub fn resign(auth: &PermissionControlAuthenticatorV1, frame: &mut [u8]) {
    let end = frame.len() - 32;
    let mac = auth.mac(&frame[..end]);
    frame[end..].copy_from_slice(&mac);
}

pub fn payload_tag_offset(context: &PermissionControlContextV1) -> usize {
    let context_bytes = 2
        + context.runtime_authority.len()
        + 16
        + 32
        + 16 * 4
        + 8
        + 8
        + 16
        + 2
        + context.idempotency_key.len()
        + 32
        + 32
        + 8
        + 8;
    4 + 19 + context_bytes
}
