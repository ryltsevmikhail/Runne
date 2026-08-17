use std::any::Any;
use std::sync::Arc;

use gocode_provider::{
    DispatchError, DispatchRequest, NativeCredentialAuthority, ProviderStreamId,
};
use gocode_provider_deepseek::{
    DeepSeekCredentialMaterializer, DeepSeekTransportPolicy, DeepSeekTransportResponse,
};
use gocode_store::provider::{
    CredentialDispatchBinding, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use tokio::time::timeout_at;

use crate::bounds::{
    ResponseContract, accepted_response_contract, append_bounded, bearer_header, record_chunk,
    wait_for_chunk,
};
use crate::{DeepSeekEffect, DeepSeekEffectError, REQUEST_ID, Sender, client, profile};

pub(super) struct AuthorizedReady {
    pub(super) request: DispatchRequest,
    pub(super) credential: CredentialDispatchBinding,
}

impl ProviderReadyEffect for AuthorizedReady {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl dyn DeepSeekEffect {
    /// Creates the production effect with mandatory native credential authority.
    pub fn production(
        authority: NativeCredentialAuthority,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        let profile = profile().map_err(|_| DeepSeekEffectError)?;
        let policy =
            DeepSeekTransportPolicy::for_profile(&profile).map_err(|_| DeepSeekEffectError)?;
        let credential =
            client::NativeCredential::versioned(authority).map_err(|_| DeepSeekEffectError)?;
        Ok(Arc::new(
            Sender::new(
                profile,
                credential,
                client::production_client(&policy).map_err(|_| DeepSeekEffectError)?,
            )
            .map_err(|_| DeepSeekEffectError)?,
        ))
    }
}

impl<C: DeepSeekCredentialMaterializer> Sender<C> {
    pub(super) async fn send_authorized(
        &self,
        ready: AuthorizedReady,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.profile.profile_digest()
        {
            return Err(DispatchError::MaybeDispatched);
        }
        let request_id = HeaderValue::from_str(ready.request.provider_idempotency_key())
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let material = self
            .credential
            .materialize(ready.credential.native_capability())
            .await
            .map_err(super::map_credential)?;
        let credential = bearer_header(&material)?;
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
                ResponseContract::Sse => DeepSeekTransportResponse::sse(vec![body]),
                ResponseContract::JsonRejection(status) => {
                    DeepSeekTransportResponse::json_rejection(status, body)
                }
            }
            .map_err(|_| DispatchError::MaybeDispatched)?;
            self.store_response(ready.request.attempt_id(), response)
        };
        timeout_at(receipt.deadline().into(), effect)
            .await
            .map_err(|_| DispatchError::MaybeDispatched)?
    }
}
