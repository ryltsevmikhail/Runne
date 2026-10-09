use super::*;

pub(super) fn connected_ready_v3_supervisor() -> (
    ProtectedBundledRuntimeSupervisor,
    UnixStream,
    runne_api::ProtectedActivationKeys,
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) {
    let (channel, daemon) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    daemon
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (process, keys) = v3_process(channel);
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!("V3 test fixture");
    };
    let owned = owned.clone();
    let root = std::env::temp_dir().join(format!("runne-mode-control-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(std::path::Path::new("/bin/sleep"), &root).unwrap();
    let supervisor = ProtectedBundledRuntimeSupervisor {
        launcher: DevelopmentBundledRuntimeLauncher::new(),
        spec,
        process: Some(process),
        pending_profile: None,
        backoff: BundledRuntimeBackoff::new(),
        restart_at: None,
        state: BundledRuntimeLifecycleState::Ready,
        permission_control_sequence: None,
    };
    let _ = std::fs::remove_dir(root);
    (supervisor, daemon, keys, owned)
}

pub(super) fn pending_context(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    epoch: u64,
) -> PermissionModeNativePendingV2 {
    let principal = ApiPrincipalId::new(owned.stable().principal_id().to_owned()).unwrap();
    let now = unix_millis().unwrap();
    let workspace = *uuid::Uuid::now_v7().as_bytes();
    PermissionModeNativePendingV2 {
        workspace_id: uuid::Uuid::from_bytes(workspace).to_string(),
        principal_id: principal.as_str().to_owned(),
        context: runne_api::PermissionModeNativePendingContextV2 {
            runtime_authority: hex::encode(owned.stable().authority_id()),
            store_lineage_id: *owned.stable().lineage_id(),
            stable_subject_digest: permission_control_stable_subject_digest_v1(&principal).unwrap(),
            protected_launch_authority_id: *owned.launch_authority_id(),
            desktop_authority_id: *owned.desktop_host_instance_id(),
            daemon_instance_id: *owned.daemon_instance_id(),
            protected_session_id: *owned.session_id(),
            launch_generation: owned.launch_generation(),
            native_key_epoch: epoch,
            command_id: uuid::Uuid::now_v7().to_string(),
            idempotency_key: "mode-change-1".to_owned(),
            public_request_digest: [4; 32],
            predecessor_transcript_digest: [0; 32],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 20_000,
        },
    }
}

pub(super) fn mode_challenge(
    pending: &PermissionModeNativePendingV2,
    context: &PermissionControlContextV1,
) -> PermissionControlModeChallengeV1 {
    PermissionControlModeChallengeV1 {
        principal: pending.principal_id.clone(),
        workspace_id: *uuid::Uuid::parse_str(&pending.workspace_id)
            .unwrap()
            .as_bytes(),
        workspace_label: "workspace".to_owned(),
        expected_authorization_revision: 0,
        requested_mode: runne_api::PermissionModeSelectionV1::RiskBased,
        preset_version: 1,
        mode_expires_at_unix_ms: None,
        managed_policy_revision: 0,
        managed_policy_digest: [5; 32],
        issued_challenge_binding_digest: [6; 32],
        ceremony_expires_at_unix_ms: context.expires_at_unix_ms,
        native_warning_version: 1,
        challenge_id: *uuid::Uuid::now_v7().as_bytes(),
        nonce: [7; 32],
    }
}
