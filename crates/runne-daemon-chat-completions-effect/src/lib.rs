#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Generic daemon effect for an exact Chat Completions profile.
use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError, ProviderCall,
    ProviderCallDigestVersion, ProviderFuture, ProviderPort, ProviderPreEffectRejection,
    ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId, ProviderStreamItem,
    ReconcileRequest, ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_provider_chat_completions::{
    ChatCompletionsProfile, ChatCompletionsRenderer, ChatCompletionsStreamDecoder,
    normalize_json_rejection,
};
use runne_provider_quota::{QuotaEvidenceSink, SubscriptionBudgetAuthority};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead, SecureStoreError,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use std::{any::Any, sync::Arc};
use tokio::time::timeout_at;
use zeroize::Zeroizing;
mod auth;
mod bounds;
mod budget;
mod constructor;
mod quota_refresh;
mod quota_refresh_transport;
mod quota_reporting;
mod streams;
mod transport;
use auth::header_name;
use bounds::{ResponseContract, accepted_response_contract, bearer_header};
use streams::StreamStore;
/// Closed generic effect error.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Chat Completions effect unavailable")]
pub struct ChatCompletionsEffectError;
pub use auth::ChatCompletionsAuthHeader;
pub use quota_refresh::AuthorizedQuotaRefresher;
pub use quota_refresh_transport::{
    QuotaRefreshResponse, QuotaRefreshTransport, QuotaRefreshTransportError,
    ReqwestQuotaRefreshTransport,
};
pub use transport::{
    ChatCompletionsTransport, ChatTransportError, ChatTransportResponse, ReqwestChatTransport,
};

/// Generic exact-profile provider effect.
pub struct ChatCompletionsEffect {
    profile: ChatCompletionsProfile,
    renderer: ChatCompletionsRenderer,
    credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
    transport: Arc<dyn ChatCompletionsTransport>,
    quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    streams: StreamStore,
    auth_header: auth::ChatCompletionsAuthHeader,
}

struct StreamReservation<'a> {
    store: &'a StreamStore,
    stream: ProviderStreamId,
    committed: bool,
}

impl Drop for StreamReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.store.remove(self.stream);
        }
    }
}

struct Ready {
    request: DispatchRequest,
    credential: CredentialDispatchBinding,
}
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl ChatCompletionsEffect {
    async fn dispatch_ready(
        &self,
        ready: Ready,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.profile.profile_digest()
        {
            return Err(DispatchError::MaybeDispatched);
        }
        if std::time::Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        let stream = ProviderStreamId::from_bytes(*ready.request.attempt_id().as_bytes());
        self.streams.reserve(stream)?;
        let mut reservation = StreamReservation {
            store: &self.streams,
            stream,
            committed: false,
        };
        let (lifecycle, fence) = ready
            .credential
            .point_of_use_revisions()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let now_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |duration| duration.as_secs().max(1));
        if quota_reporting::rejects_exhausted(
            self.quota_sink.as_ref(),
            self.profile.provider_id(),
            ready.credential.version_ref().version(),
            now_unix_seconds,
        ) {
            return Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::BudgetDenied,
            ));
        }
        let read = ProviderCredentialDispatchRead::new(
            ready.credential.native_capability(),
            lifecycle,
            fence,
            receipt.credential_read_receipt_digest(),
        )
        .map_err(|_| DispatchError::MaybeDispatched)?;
        let credential =
            self.credentials
                .materialize_active(read)
                .map_err(|error| match error {
                    SecureStoreError::ProviderCredentialNotFound => {
                        DispatchError::RejectedBeforeEffect(
                            ProviderPreEffectRejection::CredentialUnavailable,
                        )
                    }
                    _ => DispatchError::RejectedBeforeEffect(
                        ProviderPreEffectRejection::CredentialAccessDenied,
                    ),
                })?;
        let value = credential.with_bytes(|bytes| Zeroizing::new(bytes.to_vec()));
        let auth = bearer_header(&value)?;
        let url = format!("{}{}", self.profile.origin(), self.profile.path());
        let expected_url = url.clone();
        let effect = async {
            let response = self
                .transport
                .send(
                    url,
                    header_name(self.auth_header),
                    auth,
                    ready.request.prepared().rendered_bytes().to_vec(),
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
                    Ok(decoder
                        .finish()
                        .map_err(|_| DispatchError::MaybeDispatched)?)
                }
                ResponseContract::JsonRejection(status) => {
                    quota_reporting::record_zai_error(
                        self.quota_sink.as_ref(),
                        self.profile.provider_id(),
                        ready.credential.version_ref().version(),
                        now_unix_seconds,
                        &body,
                    );
                    Ok(normalize_json_rejection(status, &body)
                        .map_err(|_| DispatchError::MaybeDispatched)?)
                }
            }
        };
        let events = timeout_at(receipt.deadline().into(), effect)
            .await
            .map_err(|_| DispatchError::MaybeDispatched)??;
        let usage_events = events.clone();
        self.streams.publish(stream, events)?;
        quota_reporting::record_usage(
            self.quota_sink.as_ref(),
            self.profile.provider_id(),
            ready.credential.version_ref().version(),
            &usage_events,
        );
        budget::spend_budget(
            self.budget.as_ref(),
            self.profile.provider_id(),
            ready.credential.version_ref().version(),
            &usage_events,
        );
        reservation.committed = true;
        Ok(stream)
    }
}

impl ProviderPort for ChatCompletionsEffect {
    fn prepare(
        &self,
        call: &ProviderCall,
    ) -> Result<runne_provider::PreparedRequest, PrepareError> {
        self.renderer
            .prepare(call)
            .map_err(|error| PrepareError::Render(error.to_string()))
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<runne_provider::PreparedRequest, PrepareError> {
        if version != ProviderCallDigestVersion::V2 {
            return Err(PrepareError::UnsupportedDigestVersion(version));
        }
        self.prepare(call)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async {
            Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            ))
        })
    }
    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move { self.streams.next(*stream, cursor) })
    }
    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            self.streams.remove(request.stream_id());
            Ok(CancelDisposition::Requested)
        })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

impl ProviderEffectPort for ChatCompletionsEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            Ok(Box::new(Ready {
                request,
                credential,
            }) as Box<dyn ProviderReadyEffect>)
        })
    }
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<Ready>()
                .map_err(|_| DispatchError::MaybeDispatched)?;
            self.dispatch_ready(*ready, receipt).await
        })
    }
}
