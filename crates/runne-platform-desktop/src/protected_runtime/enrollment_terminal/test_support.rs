use super::{
    Arc, PreparedProtectedCredentialEnrollment, ProtectedBundledRuntimeError,
    ProviderCredentialOperationStateV2, finish,
};
use crate::protected_runtime::{
    TestOnlyReadyV3EnrollmentSupervisor,
    credential_discovery::{prepare, reap},
};

/// Runs the production Pair terminal reader with a protocol-only service port.
/// No native secret, writer effect or XPC endpoint is used.
///
/// # Errors
/// Rejects invalid terminal or registration transcript.
pub async fn test_only_pair_terminal(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: std::os::unix::net::UnixStream,
    tamper_ack: bool,
) -> Result<runne_api::ProviderCredentialOperationSnapshotV2, ProtectedBundledRuntimeError> {
    let (supervisor, registration) = prepare(fixture, channel, tamper_ack)?;
    let keys = runne_api::LaunchSecret::from_bytes([3; 32])
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
        .derive_keys();
    let snapshot = runne_api::ProviderCredentialOperationSnapshotV2::new(
        runne_api::ProviderCredentialOperationHandleV2::from_bytes([1; 48])
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
        None,
        runne_api::ProviderCredentialProviderV2::OpenAi,
        runne_api::ProviderCredentialOperationKindV2::Pair,
        ProviderCredentialOperationStateV2::Prepared,
        1,
        1,
        false,
        None,
    )
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    let enrollment = PreparedProtectedCredentialEnrollment {
        codec: runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(
            &keys,
        ),
        snapshot,
        relay: Some([7; 388]),
        relay_taken: true,
        #[cfg(target_os = "linux")]
        relay_fd_taken: false,
        terminal: false,
    };
    let result = finish(Arc::clone(&supervisor), enrollment, &[7; 388], registration).await;
    reap(&supervisor);
    result.map(|enrollment| enrollment.snapshot().clone())
}
