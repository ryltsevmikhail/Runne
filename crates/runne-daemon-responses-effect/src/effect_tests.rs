use super::*;
use runne_provider::{ProviderStreamEventKind, StreamCursor};
use std::sync::atomic::Ordering;
#[test]
fn exact_auth_and_endpoint_binding() {
    let profile = ResponsesProfile::new(
        runne_provider_responses_wire::ResponsesProvider::Xai,
        "grok-4",
    );
    let config = ResponsesEffectConfig {
        profile,
        auth: ResponsesAuth::XaiBearer,
    };
    assert!(
        config
            .auth
            .matches_provider_id(config.profile.provider_id())
    );
    assert!(!config.profile.endpoint().contains('{'));
    let bad = ResponsesEffectConfig {
        profile: config.profile,
        auth: ResponsesAuth::Codex {
            account_id: "acct".into(),
        },
    };
    assert!(fixture_effect(bad, Arc::new(DenyingMaterializer), Arc::new(NoTransport)).is_err());
}

#[test]
fn codex_rejects_an_under_reserved_model_profile() {
    let profile = ResponsesProfile::new(
        runne_provider_responses_wire::ResponsesProvider::OpenAiCodex,
        runne_provider_responses_wire::CODEX_MODEL,
    )
    .with_model_revision(runne_provider_responses_wire::PI_REFERENCE_REVISION)
    .with_pricing_revision_digest([1; 32])
    .with_max_output_tokens(16_384);
    let result = fixture_effect(
        ResponsesEffectConfig {
            profile,
            auth: ResponsesAuth::Codex {
                account_id: "envelope".into(),
            },
        },
        Arc::new(DenyingMaterializer),
        Arc::new(NoTransport),
    );
    assert!(matches!(result, Err(ResponsesEffectError::Profile)));
}

#[tokio::test]
async fn wrong_cursor_preserves_event_and_slot_until_terminal() {
    let profile = ResponsesProfile::new(
        runne_provider_responses_wire::ResponsesProvider::Xai,
        "grok-4",
    );
    let sender = Sender::new(
        ResponsesEffectConfig {
            profile,
            auth: ResponsesAuth::XaiBearer,
        },
        Arc::new(DenyingMaterializer),
        Arc::new(NoTransport),
    )
    .unwrap();
    let stream = ProviderStreamId::from_bytes([9; 16]);
    let event = ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap();
    sender.active_streams.fetch_add(1, Ordering::Release);
    sender
        .streams
        .lock()
        .unwrap()
        .insert(stream, VecDeque::from([event]));
    let wrong = ProviderPort::next(&sender, &stream, StreamCursor::new(1)).await;
    assert!(matches!(
        wrong,
        Err(runne_provider::StreamError::SequenceGap { .. })
    ));
    assert_eq!(sender.active_streams.load(Ordering::Acquire), 1);
    assert!(
        ProviderPort::next(&sender, &stream, StreamCursor::new(0))
            .await
            .is_ok()
    );
}

#[test]
fn stream_slots_are_bounded_and_released() {
    let count = Arc::new(AtomicUsize::new(0));
    let mut slots = (0..64)
        .map(|_| StreamSlot::reserve(Arc::clone(&count)).unwrap())
        .collect::<Vec<_>>();
    assert!(StreamSlot::reserve(Arc::clone(&count)).is_none());
    drop(slots.pop());
    assert!(StreamSlot::reserve(Arc::clone(&count)).is_some());
}
struct DenyingMaterializer;
impl ProviderCredentialDispatchMaterializer for DenyingMaterializer {
    fn materialize_active(
        &self,
        _: runne_secure_store::ProviderCredentialDispatchRead<'_>,
    ) -> Result<runne_secure_store::ProviderCredentialMaterial, runne_secure_store::SecureStoreError>
    {
        Err(runne_secure_store::SecureStoreError::CredentialAccessDenied)
    }
}
struct NoTransport;
impl ResponsesTransport for NoTransport {
    fn send<'a>(
        &'a self,
        _: &'a str,
        _: reqwest::header::HeaderMap,
        _: Vec<u8>,
    ) -> runne_provider::ProviderFuture<'a, Result<TransportResponse, DispatchError>> {
        Box::pin(async { Err(DispatchError::MaybeDispatched) })
    }
}
