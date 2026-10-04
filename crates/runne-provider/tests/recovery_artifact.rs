use runne_provider::{
    AttemptId, DispatchAttemptId, ProviderId, ProviderRecoveryAttemptIdentity,
    ProviderRecoveryBinding, ProviderRecoveryRequest, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact, RemoteResponseId, TaskRunId,
};

#[test]
fn remote_check_requires_terminal_artifact_for_terminal_status() {
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    let id = RemoteResponseId::new("resp_test").unwrap();
    assert!(
        ProviderRemoteCheck::new(
            binding,
            id.clone(),
            ProviderRemoteResponseStatus::Pending,
            None
        )
        .is_ok()
    );
    assert!(
        ProviderRemoteCheck::new(
            binding,
            id,
            ProviderRemoteResponseStatus::Completed { usage: None },
            None
        )
        .is_err()
    );
}

#[test]
fn exact_recovery_request_rejects_identity_from_another_profile() {
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    let identity = ProviderRecoveryAttemptIdentity::new(
        ProviderId::new("openai-background").unwrap(),
        ProviderId::new("openai-background").unwrap(),
        "background-text-v1",
        [5; 32],
        [6; 32],
        [7; 32],
        [8; 32],
        [9; 32],
        [10; 16],
        1,
        1,
        1,
    )
    .unwrap();
    assert!(
        ProviderRecoveryRequest::new_exact(
            binding,
            RemoteResponseId::new("resp_profile_mismatch").unwrap(),
            identity,
        )
        .is_err()
    );
}

#[test]
fn recovery_debug_redacts_remote_text_and_provider_diagnostics() {
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([1; 16]),
        AttemptId::from_bytes([2; 16]),
        DispatchAttemptId::from_bytes([3; 16]),
        [4; 32],
    )
    .unwrap();
    let id = RemoteResponseId::new("resp_test").unwrap();
    let status = ProviderRemoteResponseStatus::Failed {
        code: Some("private-diagnostic".into()),
        usage: None,
    };
    let terminal = ProviderRemoteTerminalArtifact::new(
        id.clone(),
        status.clone(),
        Some("private-output".into()),
    )
    .unwrap();
    let check = ProviderRemoteCheck::new(binding, id, status, Some(terminal)).unwrap();
    let debug = format!("{check:?}");
    assert!(!debug.contains("private"));
}
