use super::{
    Arc, BrokerControl, CredentialBrokerTransferAuthenticator, ProtectedBundledRuntimeError,
    ProviderCredentialBrokerHandoffContext, ProviderCredentialBrokerHandoffFrame, SharedControl,
    UnixStream,
};
use crate::protected_runtime::{
    TestOnlyReadyV3EnrollmentSupervisor,
    credential_discovery::{prepare, reap},
};

/// Executes a real OFFER/READY reader with a wire-only service registration port.
/// Does not spawn a writer or access XPC/Keychain.
///
/// # Errors
/// Rejects invalid broker/service evidence or changed launch ownership.
pub async fn test_only_crossed_broker_offer(
    fixture: TestOnlyReadyV3EnrollmentSupervisor,
    channel: UnixStream,
    tamper_ack: bool,
) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
    let (supervisor, registration) = prepare(fixture, channel, tamper_ack)?;
    let (bootstrap, context, auth) = {
        let guard = supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let process = guard
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let (owned, facts) = process.v3_enrollment_facts()?;
        let context = ProviderCredentialBrokerHandoffContext::new(
            *owned.stable().authority_id(),
            *owned.session_id(),
            owned.launch_generation(),
            facts.binding(),
        )
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        let captured = (
            process.recovery_bootstrap()?,
            context,
            CredentialBrokerTransferAuthenticator::from_protected_activation(&process.keys),
        );
        drop(guard);
        captured
    };
    let mut control = SharedControl {
        supervisor: Arc::clone(&supervisor),
        bootstrap,
        runtime: tokio::runtime::Handle::current(),
        registration,
    };
    let result = tokio::task::spawn_blocking(move || {
        control.offer(
            &context,
            &auth,
            ProviderCredentialBrokerHandoffFrame::PURPOSE_ENDPOINT,
        )
    })
    .await
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    reap(&supervisor);
    result
}
