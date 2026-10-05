//! Workspace-internal OpenAI provider effect boundary.

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};
use runne_provider::{
    DispatchError, DispatchRequest, ProviderPort, ProviderPreEffectRejection,
    ProviderRecoveryCapabilities, ProviderRecoveryControlAuthorizer,
    ProviderRecoveryDispatchContextProvider, ProviderStreamEvent, ProviderStreamId,
};
use runne_provider_openai::{
    OpenAiCredentialMaterializer, OpenAiResponsesTextProfile, OpenAiResponsesTextRenderer,
    OpenAiResponsesToolProfile, OpenAiResponsesToolRenderer, OpenAiTransportPolicy,
    OpenAiTransportResponse,
};
use runne_store::provider::{ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect};
use tokio::time::timeout_at;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "authorized_tool_tests.rs"]
mod authorized_tool_tests;
mod background;
mod bounds;
mod client;
mod offline_canary;
mod port_impl;
mod response;
pub use background::{
    background_recovery_capabilities, effect_from_loopback_background_fixture,
    effect_from_loopback_background_fixture_with_timeout, production_background_effect,
    production_background_effect_from_materializer,
};

#[doc(hidden)]
pub use client::FixtureRequestAuthenticator;
#[doc(hidden)]
pub use client::loopback_fixture_client;

use bounds::{
    ResponseContract, accepted_response_contract, append_bounded, bearer_header, record_chunk,
    wait_for_chunk,
};

const REQUEST_ID: HeaderName = HeaderName::from_static("x-client-request-id");

mod sealed {
    pub trait Sealed {}
}

/// Internal provider boundary; downstream crates cannot implement this trait.
pub trait OpenAiEffect: sealed::Sealed + ProviderPort + ProviderEffectPort {}

impl<T: sealed::Sealed + ProviderPort + ProviderEffectPort> OpenAiEffect for T {}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("OpenAI effect is unavailable")]
pub struct OpenAiEffectError;

/// Creates the production sender with the fixed OpenAI HTTPS client.
pub fn production_effect() -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError> {
    let profile = profile().map_err(|_| OpenAiEffectError)?;
    let policy = OpenAiTransportPolicy::for_profile(&profile).map_err(|_| OpenAiEffectError)?;
    let credential = client::NativeCredential::current_process().map_err(|_| OpenAiEffectError)?;
    Ok(Arc::new(
        Sender::new(
            profile,
            credential,
            client::production_client(&policy).map_err(|_| OpenAiEffectError)?,
        )
        .map_err(|_| OpenAiEffectError)?,
    ))
}

/// Creates the fixture-only sender and an opaque request-authentication gate.
#[doc(hidden)]
pub fn effect_from_loopback_fixture(
    client: reqwest::Client,
) -> Result<(Arc<dyn OpenAiEffect>, client::FixtureRequestAuthenticator), OpenAiEffectError> {
    let credential = client::FixtureCredential::new();
    let authenticator = credential.request_authenticator();
    let effect = Arc::new(
        Sender::new(
            profile().map_err(|_| OpenAiEffectError)?,
            credential,
            client,
        )
        .map_err(|_| OpenAiEffectError)?,
    );
    Ok((effect, authenticator))
}

/// Creates the fixture-only sender while retaining the production
/// point-of-use credential materializer boundary.
#[doc(hidden)]
pub fn effect_from_loopback_fixture_with_materializer(
    client: reqwest::Client,
    materializer: Arc<dyn runne_secure_store::ProviderCredentialDispatchMaterializer>,
) -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError> {
    let profile = profile().map_err(|_| OpenAiEffectError)?;
    let credential = client::NativeCredential::from_materializer(materializer);
    Ok(Arc::new(
        Sender::new(profile, credential, client).map_err(|_| OpenAiEffectError)?,
    ))
}

/// Creates a loopback sender with a test-owned legacy-fixture credential hook.
#[doc(hidden)]
pub fn effect_from_loopback_fixture_with_legacy_credential_materializer<C>(
    client: reqwest::Client,
    credential: C,
) -> Result<Arc<dyn OpenAiEffect>, OpenAiEffectError>
where
    C: OpenAiCredentialMaterializer + 'static,
{
    let profile = profile().map_err(|_| OpenAiEffectError)?;
    Ok(Arc::new(
        Sender::new(profile, credential, client).map_err(|_| OpenAiEffectError)?,
    ))
}

/// Builds the opaque fixture-only authorization gate before the loopback server starts.
#[doc(hidden)]
pub fn loopback_fixture_request_authenticator() -> FixtureRequestAuthenticator {
    client::FixtureCredential::new().request_authenticator()
}

/// Builds a fixture-only request authenticator for material retained by an
/// external point-of-use authority.
#[doc(hidden)]
pub fn loopback_fixture_request_authenticator_for_material(
    material: Zeroizing<Vec<u8>>,
) -> FixtureRequestAuthenticator {
    client::FixtureRequestAuthenticator::from_material(material)
}

fn profile() -> Result<OpenAiResponsesTextProfile, ()> {
    OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .map_err(|_| ())
}

struct Ready {
    request: DispatchRequest,
    credential: Zeroizing<Vec<u8>>,
}

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct Sender<C> {
    profile: OpenAiResponsesTextProfile,
    renderer: OpenAiResponsesTextRenderer,
    tool_profile: Option<OpenAiResponsesToolProfile>,
    tool_renderer: Option<OpenAiResponsesToolRenderer>,
    policy: OpenAiTransportPolicy,
    credential: C,
    client: reqwest::Client,
    streams: Mutex<BTreeMap<ProviderStreamId, VecDeque<ProviderStreamEvent>>>,
    recovery_contexts: Option<Arc<dyn ProviderRecoveryDispatchContextProvider>>,
    recovery_authorizer: Option<Arc<dyn ProviderRecoveryControlAuthorizer>>,
    recovery_capabilities: ProviderRecoveryCapabilities,
    recovery_timeout: Duration,
}

impl<C: OpenAiCredentialMaterializer> Sender<C> {
    fn expected_profile_digest(&self, tool_mode: bool) -> Option<[u8; 32]> {
        if tool_mode {
            self.tool_profile
                .as_ref()
                .map(OpenAiResponsesToolProfile::profile_digest)
        } else {
            Some(self.profile.profile_digest())
        }
    }

    fn new(
        profile: OpenAiResponsesTextProfile,
        credential: C,
        client: reqwest::Client,
    ) -> Result<Self, ()> {
        let policy = OpenAiTransportPolicy::for_profile(&profile).map_err(|_| ())?;
        let tool_profile = OpenAiResponsesToolProfile::new(profile.clone()).map_err(|_| ())?;
        let recovery_timeout = policy.total_timeout();
        Ok(Self {
            renderer: OpenAiResponsesTextRenderer::new(profile.clone()),
            tool_renderer: Some(OpenAiResponsesToolRenderer::new(tool_profile.clone())),
            tool_profile: Some(tool_profile),
            profile,
            policy,
            credential,
            client,
            streams: Mutex::new(BTreeMap::new()),
            recovery_contexts: None,
            recovery_authorizer: None,
            recovery_capabilities: ProviderRecoveryCapabilities::default(),
            recovery_timeout,
        })
    }

    async fn send_ready(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        let ready = ready.into_any().downcast::<Ready>().map_err(|_| {
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::AdapterRejected)
        })?;
        let tool_mode = !ready
            .request
            .prepared()
            .call()
            .tool_declarations()
            .is_empty();
        let expected_profile_digest = if tool_mode {
            self.tool_profile
                .as_ref()
                .map(OpenAiResponsesToolProfile::profile_digest)
        } else {
            Some(self.profile.profile_digest())
        }
        .ok_or(DispatchError::RejectedBeforeEffect(
            ProviderPreEffectRejection::AdapterRejected,
        ))?;
        if !receipt.matches_claim(ready.request.claim())
            || ready.request.claim().profile_digest != expected_profile_digest
        {
            return Err(DispatchError::MaybeDispatched);
        }
        let request_id = HeaderValue::from_str(ready.request.provider_idempotency_key())
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let credential = bearer_header(&ready.credential)?;
        let url = format!("{}{}", self.policy.origin(), self.policy.path());
        let effect = async {
            let response = self
                .client
                .post(url)
                .header(REQUEST_ID, request_id)
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
            let maximum = match contract {
                ResponseContract::Sse => self.policy.max_decoded_bytes(),
                ResponseContract::JsonRejection(_) => self.policy.max_frame_bytes(),
            };
            let mut response = response;
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
                append_bounded(&mut body, &chunk, maximum)
                    .map_err(|_| DispatchError::MaybeDispatched)?;
            }
            if body.is_empty() {
                return Err(DispatchError::MaybeDispatched);
            }
            let response = match contract {
                ResponseContract::Sse => OpenAiTransportResponse::sse(vec![body]),
                ResponseContract::JsonRejection(status) => {
                    OpenAiTransportResponse::json_rejection(status, body)
                }
            }
            .map_err(|_| DispatchError::MaybeDispatched)?;
            self.store_response(ready.request.attempt_id(), response, tool_mode)
        };
        timeout_at(receipt.deadline().into(), effect)
            .await
            .map_err(|_| DispatchError::MaybeDispatched)?
    }
}

impl<C> sealed::Sealed for Sender<C> {}
