use std::time::Duration;
use std::{collections::VecDeque, sync::Arc};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use runne_provider::{
    DispatchError, ProviderPreEffectRejection, ProviderRecoveryControlAuthorizer,
    ProviderRecoveryDispatchContextProvider, ProviderStreamId,
};
use runne_provider_openai::{
    OpenAiBackgroundCredentialMaterializer, OpenAiCredentialMaterializer,
    OpenAiResponsesTextProfile, OpenAiResponsesTextRenderer, OpenAiSseDecoder,
    OpenAiTransportPolicy, OpenAiTransportResponse,
};
use runne_store::provider::ProviderEffectStartReceipt;
use tokio::time::timeout_at;

use super::super::port_impl::authorized::AuthorizedReady;
use super::capabilities::background_recovery_capabilities;
use crate::bounds::{
    ResponseContract, accepted_response_contract, append_bounded, bearer_header, record_chunk,
    wait_for_chunk,
};
use crate::{OpenAiEffect, OpenAiEffectError, Sender, client};

/// Creates an explicitly background-profile sender with a distinct credential materializer.
pub fn production_background_effect<C: OpenAiBackgroundCredentialMaterializer + 'static>(
    credential: C,
    contexts: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    controls: Arc<dyn ProviderRecoveryControlAuthorizer>,
) -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError> {
    let profile = background_profile()?;
    let policy = OpenAiTransportPolicy::for_profile(&profile).map_err(|_| OpenAiEffectError)?;
    let recovery_timeout = policy.total_timeout();
    let client = client::production_client(&policy).map_err(|_| OpenAiEffectError)?;
    let sender = new_background_sender(
        profile,
        credential,
        client,
        contexts,
        controls,
        recovery_timeout,
    )?;
    Ok(Arc::new(sender))
}

/// Creates a loopback-only background sender for transport contract tests.
#[doc(hidden)]
pub fn effect_from_loopback_background_fixture(
    client: reqwest::Client,
    contexts: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    controls: Arc<dyn ProviderRecoveryControlAuthorizer>,
) -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError> {
    effect_from_loopback_background_fixture_with_timeout(
        client,
        contexts,
        controls,
        OpenAiTransportPolicy::for_profile(&background_profile()?)
            .map_err(|_| OpenAiEffectError)?
            .total_timeout(),
    )
}

/// Creates a loopback fixture sender with a shortened recovery-operation deadline.
#[doc(hidden)]
pub fn effect_from_loopback_background_fixture_with_timeout(
    client: reqwest::Client,
    contexts: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    controls: Arc<dyn ProviderRecoveryControlAuthorizer>,
    recovery_timeout: Duration,
) -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError> {
    let profile = background_profile()?;
    let credential = client::FixtureCredential::new();
    Ok(Arc::new(new_background_sender(
        profile,
        credential,
        client,
        contexts,
        controls,
        recovery_timeout,
    )?))
}

fn background_profile() -> Result<OpenAiResponsesTextProfile, OpenAiEffectError> {
    OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .map_err(|_| OpenAiEffectError)
}

pub(crate) fn new_background_sender<C: OpenAiBackgroundCredentialMaterializer>(
    profile: OpenAiResponsesTextProfile,
    credential: C,
    client: reqwest::Client,
    contexts: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    controls: Arc<dyn ProviderRecoveryControlAuthorizer>,
    recovery_timeout: Duration,
) -> Result<Sender<C>, OpenAiEffectError> {
    if !profile.is_background() {
        return Err(OpenAiEffectError);
    }
    let policy = OpenAiTransportPolicy::for_profile(&profile).map_err(|_| OpenAiEffectError)?;
    let recovery_timeout = recovery_timeout.min(policy.total_timeout());
    Ok(Sender {
        renderer: OpenAiResponsesTextRenderer::new(profile.clone()),
        profile,
        policy,
        credential,
        client,
        streams: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        recovery_contexts: Some(contexts),
        recovery_authorizer: Some(controls),
        recovery_timeout,
        recovery_capabilities: background_recovery_capabilities(),
    })
}

impl<C: OpenAiCredentialMaterializer> Sender<C> {
    pub(crate) async fn send_background_authorized(
        &self,
        ready: AuthorizedReady,
        mut receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        let claim = ready.request.claim();
        if !receipt.matches_claim(claim)
            || !receipt.matches_credential(&ready.credential)
            || claim.profile_digest != self.profile.profile_digest()
            || ready.credential.version_ref().provider().as_str() != "openai-background"
        {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::ProfileRejected,
            ));
        }
        let final_send = receipt.take_final_send_authority().map_err(|_| {
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
        })?;
        let contexts = self.recovery_contexts.as_ref().ok_or({
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::ProfileRejected)
        })?;
        let background_realm =
            runne_provider::ProviderId::new("openai-background").map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::ProfileRejected)
            })?;
        let rendered = ready.request.prepared().rendered_bytes();
        let context = contexts
            .for_persisted_new_dispatch(
                claim,
                &background_realm,
                &background_realm,
                self.profile.profile_id(),
                rendered,
            )
            .await
            .map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::ProfileRejected)
            })?;
        if !context.matches_claim(claim.attempt_id, claim.profile_digest) {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::ProfileRejected,
            ));
        }
        let identity = context
            .identity()
            .ok_or(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::ProfileRejected,
            ))?;
        if identity.provider_id().as_str() != "openai-background"
            || identity.credential_realm().as_str() != "openai-background"
            || identity.profile_id() != self.profile.profile_id()
            || identity.profile_digest() != &claim.profile_digest
            || identity.prepared_digest() != ready.request.prepared().request_ref().as_bytes()
            || identity.request_digest() != ready.request.prepared().render_digest()
        {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::ProfileRejected,
            ));
        }
        let request_id =
            HeaderValue::from_str(ready.request.provider_idempotency_key()).map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
        let material = match ready.credential.point_of_use_revisions() {
            Ok((lifecycle, fence)) => {
                self.credential
                    .materialize(
                        ready.credential.native_capability(),
                        lifecycle,
                        fence,
                        receipt.credential_read_receipt_digest(),
                    )
                    .await
            }
            Err(_) => {
                self.credential
                    .materialize_legacy_fixture(
                        ready.credential.native_capability(),
                        receipt.credential_read_receipt_digest(),
                    )
                    .await
            }
        }
        .map_err(super::super::port_impl::map_credential)?;
        let credential = bearer_header(&material)?;
        let url = format!("{}{}", self.policy.origin(), self.policy.path());
        let response = async {
            final_send.consume().map_err(|_| {
                DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
            })?;
            let mut response = self
                .client
                .post(url)
                .header(super::super::REQUEST_ID, request_id)
                .header(AUTHORIZATION, credential)
                .header(CONTENT_TYPE, "application/json")
                .body(ready.request.prepared().rendered_bytes().to_vec())
                .send()
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            let contract = accepted_response_contract(
                response.url().as_str(),
                response.status().as_u16(),
                response
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
            )
            .ok_or(DispatchError::MaybeDispatched)?;
            match contract {
                ResponseContract::Sse => {
                    let mut decoder = OpenAiSseDecoder::background();
                    let mut events = VecDeque::new();
                    let mut chunks = 0;
                    let mut committed = false;
                    loop {
                        let chunk = wait_for_chunk(self.policy.idle_timeout(), response.chunk())
                            .await
                            .map_err(|_| DispatchError::MaybeDispatched)?
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                        let Some(chunk) = chunk else { break };
                        record_chunk(&mut chunks, self.policy.max_transport_chunks())
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                        decoder
                            .append_background_fragment(&chunk)
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                        while decoder
                            .process_background_frame()
                            .map_err(|_| DispatchError::MaybeDispatched)?
                        {
                            if !committed && let Some(value) = decoder.background_response_id() {
                                let id = runne_provider::RemoteResponseId::new(value)
                                    .map_err(|_| DispatchError::MaybeDispatched)?;
                                self.policy
                                    .status_url(&id)
                                    .map_err(|_| DispatchError::MaybeDispatched)?;
                                context
                                    .commit_response_id(&id)
                                    .await
                                    .map_err(|_| DispatchError::MaybeDispatched)?;
                                committed = true;
                            }
                            events.extend(decoder.take_background_events());
                        }
                    }
                    events.extend(
                        decoder
                            .finish()
                            .map_err(|_| DispatchError::MaybeDispatched)?,
                    );
                    if !committed {
                        return Err(DispatchError::MaybeDispatched);
                    }
                    self.store_events(ready.request.attempt_id(), events.into_iter().collect())
                }
                ResponseContract::JsonRejection(status) => {
                    let mut body = Vec::new();
                    let mut chunks = 0;
                    loop {
                        let chunk = wait_for_chunk(self.policy.idle_timeout(), response.chunk())
                            .await
                            .map_err(|_| DispatchError::MaybeDispatched)?
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                        let Some(chunk) = chunk else { break };
                        record_chunk(&mut chunks, self.policy.max_transport_chunks())
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                        append_bounded(&mut body, &chunk, self.policy.max_frame_bytes())
                            .map_err(|_| DispatchError::MaybeDispatched)?;
                    }
                    let rejected = OpenAiTransportResponse::json_rejection(status, body)
                        .map_err(|_| DispatchError::MaybeDispatched)?;
                    self.store_response(ready.request.attempt_id(), rejected)
                }
            }
        };
        timeout_at(receipt.deadline().into(), response)
            .await
            .map_err(|_| DispatchError::MaybeDispatched)?
    }
}
