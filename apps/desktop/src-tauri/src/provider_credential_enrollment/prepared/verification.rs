use super::{PreparedCredentialEnrollmentError, PreparedCredentialEnrollmentExchange};
use runne_api::{
    ProviderCredentialOperationKindV2, ProviderCredentialOperationStateV2,
    ProviderCredentialVerificationKindV2, VerifyProviderCredential,
};
use runne_platform_desktop::NativeProtectedCredentialVerificationBegin;

/// Runs the control-only protected transcript for an explicit quota read.
pub(super) fn run(
    exchange: &PreparedCredentialEnrollmentExchange,
    native_intent_id: &str,
) -> Result<(), PreparedCredentialEnrollmentError> {
    let command_id = uuid::Uuid::now_v7().to_string();
    let command = VerifyProviderCredential::new(
        exchange.request.provider,
        exchange.request.expected_revision,
        ProviderCredentialVerificationKindV2::Remote,
        &command_id,
        native_intent_id,
    )
    .map_err(|_| PreparedCredentialEnrollmentError)?;
    let begin =
        NativeProtectedCredentialVerificationBegin::new(command, exchange.native_confirmation)
            .map_err(|_| PreparedCredentialEnrollmentError)?;
    let supervisor = exchange.resources.runtime.supervisor_handle();
    let enrollment = supervisor
        .lock()
        .map_err(|_| PreparedCredentialEnrollmentError)?
        .begin_protected_credential_verification(begin)
        .map_err(|_| PreparedCredentialEnrollmentError)?;
    let snapshot = enrollment.snapshot();
    if !enrollment.terminal()
        || snapshot.operation_kind() != ProviderCredentialOperationKindV2::VerifyRemote
        || snapshot.provider_id() != exchange.request.provider
        || snapshot.state() != ProviderCredentialOperationStateV2::Completed
    {
        return Err(PreparedCredentialEnrollmentError);
    }
    Ok(())
}
