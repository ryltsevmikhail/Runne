use runne_provider::{
    ProviderRecoveryError, ProviderRecoveryOperation, ProviderRecoveryRequest, ProviderRemoteCheck,
    ProviderRemoteResponseStatus,
};
use runne_provider_openai::{OpenAiBackgroundResponse, OpenAiValidatedBackgroundTerminal};

use super::transport::authorized_request;
use crate::Sender;

pub(crate) async fn cancel_remote<C>(
    sender: &Sender<C>,
    request: ProviderRecoveryRequest,
) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
    if !sender.recovery_capabilities.remote_cancel {
        return Err(ProviderRecoveryError::Unsupported);
    }
    let url = sender
        .policy
        .cancellation_url(request.response_id())
        .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
    let response = authorized_request(
        sender,
        &request,
        ProviderRecoveryOperation::RemoteCancel,
        reqwest::Method::POST,
        url,
    )
    .await?;
    cancel_response(sender, &request, &response.bytes, response.proof)
}

fn cancel_response<C>(
    sender: &Sender<C>,
    request: &ProviderRecoveryRequest,
    bytes: &[u8],
    proof: runne_provider::ProviderRemoteOperationProof,
) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
    if bytes.is_empty() {
        return ProviderRemoteCheck::new_authorized(
            request.binding(),
            request.response_id().clone(),
            ProviderRemoteResponseStatus::Unknown,
            None,
            ProviderRecoveryOperation::RemoteCancel,
            proof,
        );
    }
    let envelope = OpenAiBackgroundResponse::from_json_for_profile(
        bytes,
        &sender.profile,
        request.response_id(),
    )?;
    if matches!(
        envelope.status(),
        ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown
    ) {
        let check = envelope.into_nonterminal_check(request.binding())?;
        return attach_cancel_proof(check, proof);
    }
    let check =
        OpenAiValidatedBackgroundTerminal::from_json(bytes, &sender.profile, request.response_id())
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)?
            .into_remote_check(request.binding())?;
    attach_cancel_proof(check, proof)
}

fn attach_cancel_proof(
    check: ProviderRemoteCheck,
    proof: runne_provider::ProviderRemoteOperationProof,
) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
    ProviderRemoteCheck::new_authorized(
        check.binding(),
        check.response_id().clone(),
        check.status().clone(),
        check.terminal().cloned(),
        ProviderRecoveryOperation::RemoteCancel,
        proof,
    )
}
