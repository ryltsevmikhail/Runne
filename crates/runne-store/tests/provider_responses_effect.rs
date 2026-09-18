#![allow(dead_code)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_daemon_responses_effect::{
    ResponsesAuth, ResponsesEffectConfig, ResponsesTransport, TransportResponse, fixture_effect,
};
use runne_provider::{DispatchError, ProviderFuture, ProviderStreamEventKind, StreamCursor};
use runne_secure_store::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
    ProviderCredentialMaterial, SecureStoreError,
};
use runne_store::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
};

#[path = "support/provider_responses_effect/fixture.rs"]
mod fixture;

#[path = "support/online_credential_fixture.rs"]
mod online_credential_fixture;
#[path = "support/online_proof.rs"]
mod online_proof;
#[path = "support/validated_reopen.rs"]
mod validated_reopen;

use fixture::{fixture, response_body};

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
}
impl ProviderCredentialDispatchMaterializer for Materializer {
    fn materialize_active(
        &self,
        read: ProviderCredentialDispatchRead<'_>,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny.load(Ordering::SeqCst) {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        assert_eq!(read.capability().version_ref().provider().as_str(), "xai");
        ProviderCredentialMaterial::new(b"fixture-token".to_vec())
    }
}

struct Transport {
    calls: AtomicUsize,
    bodies: Mutex<Vec<Vec<u8>>>,
    body: Vec<u8>,
}
impl ResponsesTransport for Transport {
    fn send<'a>(
        &'a self,
        url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> ProviderFuture<'a, Result<TransportResponse, DispatchError>> {
        let expected = "https://api.x.ai/v1/responses";
        let valid_auth = headers
            .get(reqwest::header::AUTHORIZATION)
            .is_some_and(|h| h.is_sensitive());
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies.lock().unwrap().push(body);
        let response = TransportResponse {
            url: url.to_owned(),
            status: if url == expected && valid_auth {
                200
            } else {
                401
            },
            content_type: Some("text/event-stream".into()),
            body: self.body.clone(),
        };
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_receipt_materializes_then_dispatches_and_normalizes_usage() {
    let fixture = fixture();
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(false),
    });
    let transport = Arc::new(Transport {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        body: response_body(),
    });
    let effect = fixture_effect(
        ResponsesEffectConfig {
            profile: fixture.profile.clone(),
            auth: ResponsesAuth::XaiBearer,
        },
        materializer.clone(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    let outcome = coordinator.dispatch(fixture.request).await.unwrap();
    let binding = match outcome {
        ProviderCoordinatorOutcome::Streaming { binding } => binding,
        other => panic!("unexpected outcome: {other:?}"),
    };
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    let stream = binding.execution().stream_id();
    let started = effect.next(&stream, StreamCursor::new(0)).await.unwrap();
    assert!(matches!(
        started.event().kind(),
        ProviderStreamEventKind::Started
    ));
    let delta = effect.next(&stream, StreamCursor::new(1)).await.unwrap();
    assert!(
        matches!(delta.event().kind(), ProviderStreamEventKind::TextDelta { text } if text == "hello")
    );
    let usage = effect.next(&stream, StreamCursor::new(2)).await.unwrap();
    assert!(
        matches!(usage.event().kind(), ProviderStreamEventKind::Usage { usage } if usage.total_tokens() == 10)
    );
    let terminal = effect.next(&stream, StreamCursor::new(3)).await.unwrap();
    assert!(matches!(
        terminal.event().kind(),
        ProviderStreamEventKind::Finished { .. }
    ));
    assert!(effect.next(&stream, StreamCursor::new(4)).await.is_err());
    let body = transport.bodies.lock().unwrap().first().cloned().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["model"], "grok-4");
    assert_eq!(body["stream"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn credential_denial_after_real_receipt_does_not_call_transport() {
    let fixture = fixture();
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(true),
    });
    let transport = Arc::new(Transport {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        body: response_body(),
    });
    let effect = fixture_effect(
        ResponsesEffectConfig {
            profile: fixture.profile.clone(),
            auth: ResponsesAuth::XaiBearer,
        },
        materializer.clone(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    assert!(matches!(
        coordinator.dispatch(fixture.request).await,
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_remote_stream_is_uncertain_after_transport_boundary() {
    let fixture = fixture();
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(false),
    });
    let transport = Arc::new(Transport {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        body: b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n".to_vec(),
    });
    let effect = fixture_effect(
        ResponsesEffectConfig {
            profile: fixture.profile.clone(),
            auth: ResponsesAuth::XaiBearer,
        },
        materializer.clone(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    assert!(matches!(
        coordinator.dispatch(fixture.request).await,
        Ok(ProviderCoordinatorOutcome::Uncertain)
    ));
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_profile_binding_is_rejected_before_materialization_or_transport() {
    let fixture = fixture();
    let materializer = Arc::new(Materializer {
        calls: AtomicUsize::new(0),
        deny: AtomicBool::new(false),
    });
    let transport = Arc::new(Transport {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        body: response_body(),
    });
    let effect = fixture_effect(
        ResponsesEffectConfig {
            profile: fixture.profile.clone(),
            auth: ResponsesAuth::XaiBearer,
        },
        materializer.clone(),
        transport.clone(),
    )
    .unwrap();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &fixture.dispatch,
        &fixture.execution,
        CredentialDispatchAuthority::new(&fixture.credential, &fixture.launch),
        effect.as_ref(),
        effect.as_ref(),
        &Guard,
    );
    let mut request = fixture.request;
    request.profile_digest = [99; 32];
    assert!(coordinator.dispatch(request).await.is_err());
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
}
