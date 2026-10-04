use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use runne_provider::{
    ProviderRecoveryError, ProviderRecoveryOperation, ProviderRecoveryRequest,
    ProviderRemoteOperationProof,
};
use runne_provider_openai::OPENAI_MAX_BACKGROUND_STATUS_BYTES;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::{
    Sender,
    bounds::{append_bounded, bearer_header, record_chunk, wait_for_chunk},
};

pub(super) async fn authorized_request<C>(
    sender: &Sender<C>,
    request: &ProviderRecoveryRequest,
    operation: ProviderRecoveryOperation,
    method: reqwest::Method,
    url: String,
) -> Result<AuthorizedResponse, ProviderRecoveryError> {
    if !sender.profile.is_background()
        || request.binding().profile_digest() != sender.profile.profile_digest()
    {
        return Err(ProviderRecoveryError::InvalidIdentity);
    }
    let authorizer = sender
        .recovery_authorizer
        .as_ref()
        .ok_or(ProviderRecoveryError::Unsupported)?;
    authorized_request_with_timeout(
        sender,
        request,
        authorizer.as_ref(),
        operation,
        method,
        url,
        sender.recovery_timeout,
    )
    .await
}

async fn authorized_request_with_timeout<C>(
    sender: &Sender<C>,
    request: &ProviderRecoveryRequest,
    authorizer: &dyn runne_provider::ProviderRecoveryControlAuthorizer,
    operation: ProviderRecoveryOperation,
    method: reqwest::Method,
    url: String,
    total_timeout: Duration,
) -> Result<AuthorizedResponse, ProviderRecoveryError> {
    tokio::time::timeout(total_timeout, async {
        let authorization = authorizer
            .authorize_and_materialize(request, operation)
            .await?;
        if !authorization
            .proof()
            .matches(request.binding(), operation, request.response_id())
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let bytes = read_json(sender, method, url, authorization.credential()).await?;
        Ok(AuthorizedResponse {
            bytes,
            proof: authorization.proof().clone(),
        })
    })
    .await
    .map_err(|_| ProviderRecoveryError::Unavailable)?
}

pub(super) struct AuthorizedResponse {
    pub(super) bytes: Vec<u8>,
    pub(super) proof: ProviderRemoteOperationProof,
}

async fn read_json<C>(
    sender: &Sender<C>,
    method: reqwest::Method,
    url: String,
    material: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, ProviderRecoveryError> {
    let mut response = sender
        .client
        .request(method, url.clone())
        .header(
            AUTHORIZATION,
            bearer_header(material).map_err(|_| ProviderRecoveryError::Unavailable)?,
        )
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
    if response.url().as_str() != url {
        return Err(ProviderRecoveryError::Unavailable);
    }
    if response.status().as_u16() == 404 {
        return Ok(Vec::new());
    }
    if response.status().as_u16() != 200
        || response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            != Some("application/json")
    {
        return Err(ProviderRecoveryError::Unavailable);
    }
    let mut body = Vec::new();
    let mut chunks = 0;
    loop {
        let chunk = wait_for_chunk(sender.policy.idle_timeout(), response.chunk())
            .await
            .map_err(|_| ProviderRecoveryError::Unavailable)?
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let Some(chunk) = chunk else { break };
        record_chunk(&mut chunks, sender.policy.max_transport_chunks())
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        append_bounded(&mut body, &chunk, OPENAI_MAX_BACKGROUND_STATUS_BYTES)
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
    }
    if body.is_empty() {
        return Err(ProviderRecoveryError::Unavailable);
    }
    Ok(body)
}
