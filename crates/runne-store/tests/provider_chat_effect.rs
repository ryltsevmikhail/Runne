use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_daemon_chat_completions_effect::{
    ChatCompletionsAuthHeader, ChatCompletionsEffect, ChatCompletionsTransport,
    ChatTransportResponse,
};
use runne_provider::{ProviderFuture, ProviderPort, ProviderStreamEventKind, StreamCursor};
use runne_provider_quota::{
    QuotaEvidenceSink, QuotaIdentity, QuotaObservationSource, QuotaSnapshot, QuotaStateStore,
    QuotaWindow, QuotaWindowKind,
};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, ProviderEffectPort,
    ProviderEffectStartReceipt, ProviderReadyEffect, SqliteProviderDispatchCoordinator,
};

#[path = "support/provider_chat_effect/fixture.rs"]
mod fixture;
#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

struct Guard;
impl ProhibitedContentPort for Guard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

struct Materializer {
    calls: AtomicUsize,
    deny: AtomicBool,
    provider: String,
}
impl ProviderCredentialDispatchMaterializer for Materializer {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            read.capability().version_ref().provider().as_str(),
            self.provider
        );
        if self.deny.load(Ordering::SeqCst) {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        ProviderCredentialMaterial::new(b"fixture-token".to_vec())
    }
}

struct Transport {
    calls: AtomicUsize,
    bodies: Mutex<Vec<Vec<u8>>>,
    expected_url: String,
    body: Vec<u8>,
}

struct DelayedDispatch<'a> {
    inner: &'a ChatCompletionsEffect,
    delay: std::time::Duration,
}

impl ProviderEffectPort for DelayedDispatch<'_> {
    fn stage_effect(
        &self,
        request: runne_provider::DispatchRequest,
        credential: runne_store::provider::CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, runne_provider::DispatchError>>
    {
        self.inner.stage_effect(request, credential)
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<runne_provider::ProviderStreamId, runne_provider::DispatchError>>
    {
        let inner = self.inner;
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            inner.dispatch_effect(ready, receipt).await
        })
    }
}
impl ChatCompletionsTransport for Transport {
    fn send(
        &self,
        url: String,
        _: reqwest::header::HeaderName,
        value: reqwest::header::HeaderValue,
        body: Vec<u8>,
    ) -> ProviderFuture<
        '_,
        Result<ChatTransportResponse, runne_daemon_chat_completions_effect::ChatTransportError>,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies.lock().unwrap().push(body);
        let status = if url == self.expected_url && value.is_sensitive() {
            200
        } else {
            401
        };
        let response = ChatTransportResponse {
            url,
            status,
            content_type: Some("text/event-stream".into()),
            body: self.body.clone(),
        };
        Box::pin(async move { Ok(response) })
    }
}

async fn dispatch(
    provider: &str,
    quota: Option<Arc<dyn QuotaEvidenceSink>>,
    authority_ttl_seconds: u64,
) -> (
    usize,
    usize,
    Option<Vec<runne_provider::ProviderStreamEventKind>>,
) {
    let fixture = fixture::fixture_with_ttl(provider, authority_ttl_seconds);
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(false),
        provider: provider.into(),
    });
    let transport = Arc::new(Transport {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        expected_url: format!("{}{}", fixture.profile.origin(), fixture.profile.path()),
        body: fixture::response_body(fixture.profile.model_id()),
    });
    let effect = ChatCompletionsEffect::new_with_transport(
        fixture.profile.clone(),
        materializer.clone(),
        quota,
        ChatCompletionsAuthHeader::Authorization,
        transport.clone(),
    )
    .unwrap();
    let outcome = if authority_ttl_seconds <= 1 {
        let delayed = DelayedDispatch {
            inner: &effect,
            delay: std::time::Duration::from_secs(121),
        };
        let coordinator = SqliteProviderDispatchCoordinator::new(
            &fixture.dispatch,
            &fixture.execution,
            CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
            &effect,
            &delayed,
            &Guard,
        );
        coordinator.dispatch(fixture.request).await
    } else {
        let coordinator = SqliteProviderDispatchCoordinator::new(
            &fixture.dispatch,
            &fixture.execution,
            CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
            &effect,
            &effect,
            &Guard,
        );
        coordinator.dispatch(fixture.request).await
    };
    let kinds = match outcome {
        Ok(ProviderCoordinatorOutcome::Streaming { binding }) => {
            let stream = binding.execution().stream_id();
            let mut cursor = StreamCursor::new(0);
            let mut kinds = Vec::new();
            while let Ok(item) = effect.next(&stream, cursor).await {
                kinds.push(item.event().kind().clone());
                cursor = StreamCursor::new(cursor.sequence() + 1);
            }
            Some(kinds)
        }
        Ok(ProviderCoordinatorOutcome::Uncertain) | Err(_) => None,
        other => panic!("unexpected coordinator outcome: {other:?}"),
    };
    (
        materializer.calls.load(Ordering::SeqCst),
        transport.calls.load(Ordering::SeqCst),
        kinds,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_dispatches_payg_and_normalizes_terminal_usage() {
    let (reads, calls, kinds) = dispatch("openrouter", None, 120).await;
    assert_eq!((reads, calls), (1, 1));
    let kinds = kinds.unwrap();
    assert!(kinds.iter().any(
        |kind| matches!(kind, ProviderStreamEventKind::TextDelta { text } if text == "hello")
    ));
    assert!(kinds.iter().any(|kind| matches!(kind, ProviderStreamEventKind::Usage { usage } if usage.total_tokens() == 10)));
    assert!(
        kinds
            .iter()
            .any(|kind| matches!(kind, ProviderStreamEventKind::Finished { .. }))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_dispatches_subscription_with_external_xxx_accounting() {
    let (reads, calls, kinds) = dispatch("zai", None, 120).await;
    assert_eq!((reads, calls), (1, 1));
    assert!(kinds.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_subscription_is_rejected_before_materialization_and_http() {
    let store = QuotaStateStore::new();
    let identity = QuotaIdentity::new("zai", 1).unwrap();
    store
        .record_snapshot(
            QuotaSnapshot::new(
                identity,
                QuotaObservationSource::ProviderApi,
                100,
                vec![
                    QuotaWindow::new(
                        QuotaWindowKind::TokenQuotaUnspecified,
                        None,
                        None,
                        Some(0),
                        None,
                        None,
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        )
        .unwrap();
    let (reads, calls, kinds) = dispatch("zai", Some(Arc::new(store)), 120).await;
    assert_eq!((reads, calls, kinds.is_some()), (0, 0, false));
}

#[tokio::test(flavor = "current_thread")]
async fn expired_sqlite_receipt_is_rejected_before_materialization_and_http() {
    let (reads, calls, kinds) = dispatch("openrouter", None, 1).await;
    assert_eq!((reads, calls, kinds.is_some()), (0, 0, false));
}
