use runne_provider::{
    ProviderRecoveryError, ProviderRecoveryOperation, ProviderRecoveryRequest, ProviderRemoteCheck,
    ProviderRemoteResponseStatus,
};
use runne_provider_openai::{OpenAiBackgroundResponse, OpenAiValidatedBackgroundTerminal};

use super::transport::authorized_request;
use crate::Sender;

pub(crate) async fn check_remote_status<C>(
    sender: &Sender<C>,
    request: ProviderRecoveryRequest,
) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
    if !sender.recovery_capabilities.status_check {
        return Err(ProviderRecoveryError::Unsupported);
    }
    let url = sender
        .policy
        .status_url(request.response_id())
        .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
    let response = authorized_request(
        sender,
        &request,
        ProviderRecoveryOperation::StatusCheck,
        reqwest::Method::GET,
        url,
    )
    .await?;
    check_response(sender, &request, &response.bytes, response.proof)
}

fn check_response<C>(
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
            ProviderRecoveryOperation::StatusCheck,
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
        return attach_proof(check, ProviderRecoveryOperation::StatusCheck, proof);
    }
    let check =
        OpenAiValidatedBackgroundTerminal::from_json(bytes, &sender.profile, request.response_id())
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)?
            .into_remote_check(request.binding());
    attach_proof(check?, ProviderRecoveryOperation::StatusCheck, proof)
}

fn attach_proof(
    check: ProviderRemoteCheck,
    operation: ProviderRecoveryOperation,
    proof: runne_provider::ProviderRemoteOperationProof,
) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
    ProviderRemoteCheck::new_authorized(
        check.binding(),
        check.response_id().clone(),
        check.status().clone(),
        check.terminal().cloned(),
        operation,
        proof,
    )
}
