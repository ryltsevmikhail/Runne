use super::{ChatCompletionsEffect, Ready};
use crate::auth::header_name;
use crate::bounds::{ResponseContract, accepted_response_contract, bearer_header};
use crate::quota_reporting;
use runne_provider::{DispatchError, ProviderStreamEvent};
use runne_provider_chat_completions::{ChatCompletionsStreamDecoder, normalize_json_rejection};
use runne_store::provider::ProviderFinalSendAuthority;
use zeroize::Zeroizing;

impl ChatCompletionsEffect {
    /// Sends the bounded provider request and normalizes one accepted response.
    pub(super) async fn send_dispatch_effect(
        &self,
        ready: &Ready,
        value: &Zeroizing<Vec<u8>>,
        now_unix_seconds: u64,
        final_send: ProviderFinalSendAuthority,
    ) -> Result<Vec<ProviderStreamEvent>, DispatchError> {
        let auth = bearer_header(value)?;
        let url = format!("{}{}", self.profile.origin(), self.profile.path());
        let expected_url = url.clone();
        let response = self
            .transport
            .send(
                url,
                header_name(self.auth_header),
                auth,
                ready.request.prepared().rendered_bytes().to_vec(),
                final_send,
            )
            .await
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let status = response.status;
        let contract = accepted_response_contract(
            &expected_url,
            &response.url,
            status,
            response.content_type.as_deref(),
        )
        .ok_or(DispatchError::MaybeDispatched)?;
        let body = response.body;
        if body.len() > self.profile.max_request_bytes() {
            return Err(DispatchError::MaybeDispatched);
        }
        if body.is_empty() {
            return Err(DispatchError::MaybeDispatched);
        }
        match contract {
            ResponseContract::Sse => {
                let mut decoder = ChatCompletionsStreamDecoder::for_profile(&self.profile);
                decoder
                    .push(&body)
                    .map_err(|_| DispatchError::MaybeDispatched)?;
                decoder.finish().map_err(|_| DispatchError::MaybeDispatched)
            }
            ResponseContract::JsonRejection(status) => {
                quota_reporting::record_zai_error(
                    self.quota_sink.as_ref(),
                    self.profile.provider_id(),
                    ready.credential.version_ref().version(),
                    now_unix_seconds,
                    &body,
                );
                normalize_json_rejection(status, &body).map_err(|_| DispatchError::MaybeDispatched)
            }
        }
    }
}
