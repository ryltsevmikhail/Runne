mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gocode_provider::{
    CancelDisposition, CancelRequest, DispatchAttemptId, DispatchError, ProviderFuture,
    ProviderPort, ProviderPreEffectRejection, ProviderStreamEventKind, ReconcileRequest,
    ReconciliationDisposition, StreamCursor,
};
use gocode_provider_openai::{
    OPENAI_MAX_TRANSPORT_CHUNKS, OpenAiCredentialError, OpenAiCredentialMaterializer,
    OpenAiProviderAdapter, OpenAiTransport, OpenAiTransportError, OpenAiTransportRequest,
    OpenAiTransportResponse,
};
use zeroize::Zeroizing;

type Observation = (String, String, String, usize, usize);
type Observations = Arc<Mutex<Vec<Observation>>>;
type TestAdapter = OpenAiProviderAdapter<FixtureTransport, FixtureCredential>;
type AdapterFixture = (TestAdapter, Observations, Arc<AtomicUsize>);

#[derive(Clone)]
struct FixtureTransport {
    response: Result<OpenAiTransportResponse, OpenAiTransportError>,
    observations: Observations,
}

impl OpenAiTransport for FixtureTransport {
    fn send(
        &self,
        request: OpenAiTransportRequest,
    ) -> ProviderFuture<'_, Result<OpenAiTransportResponse, OpenAiTransportError>> {
        let response = self.response.clone();
        let observations = Arc::clone(&self.observations);
        Box::pin(async move {
            observations.lock().expect("observations").push((
                request.origin().to_owned(),
                request.path().to_owned(),
                request.request_id().to_owned(),
                request.body().len(),
                request.credential().len(),
            ));
            response
        })
    }
}

#[derive(Clone)]
struct FixtureCredential {
    result: Result<Vec<u8>, OpenAiCredentialError>,
    calls: Arc<AtomicUsize>,
}

impl OpenAiCredentialMaterializer for FixtureCredential {
    fn materialize(&self) -> Result<Zeroizing<Vec<u8>>, OpenAiCredentialError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone().map(Zeroizing::new)
    }
}

fn adapter(
    response: Result<OpenAiTransportResponse, OpenAiTransportError>,
    credential: Result<Vec<u8>, OpenAiCredentialError>,
) -> AdapterFixture {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let credential_calls = Arc::new(AtomicUsize::new(0));
    let adapter = OpenAiProviderAdapter::new(
        support::profile(),
        FixtureTransport {
            response,
            observations: Arc::clone(&observations),
        },
        FixtureCredential {
            result: credential,
            calls: Arc::clone(&credential_calls),
        },
    )
    .expect("adapter");
    (adapter, observations, credential_calls)
}

fn sse(body: Vec<u8>) -> OpenAiTransportResponse {
    OpenAiTransportResponse::sse(vec![body]).expect("bounded SSE fixture")
}

#[tokio::test]
async fn completed_stream_conforms_to_provider_port_and_exact_request_binding() {
    let (adapter, observations, credential_calls) = adapter(
        Ok(sse(support::successful_sse())),
        Ok(b"fixture-key".to_vec()),
    );
    let profile = support::profile();
    let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
    let replay_prepared = prepared.clone();
    let expected_body_len = prepared.rendered_bytes().len();
    let attempt = DispatchAttemptId::from_bytes([3; 16]);
    let stream = adapter
        .dispatch(support::dispatch_request(
            prepared,
            attempt,
            "gocode-attempt-0001",
            &profile,
        ))
        .await
        .expect("dispatch");

    let mut events = Vec::new();
    for cursor in 0..5 {
        events.push(
            adapter
                .next(&stream, StreamCursor::new(cursor))
                .await
                .expect("stream item"),
        );
    }
    assert!(matches!(
        events.last().map(|item| item.event().kind()),
        Some(ProviderStreamEventKind::Finished { .. })
    ));
    assert_eq!(credential_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observations.lock().expect("observations").as_slice(),
        &[(
            "https://api.openai.com".to_owned(),
            "/v1/responses".to_owned(),
            "gocode-attempt-0001".to_owned(),
            expected_body_len,
            11,
        )]
    );
    assert_eq!(
        adapter
            .reconcile(ReconcileRequest::new(attempt))
            .await
            .expect("reconcile"),
        ReconciliationDisposition::Settled
    );
    assert_eq!(
        adapter
            .dispatch(support::dispatch_request(
                replay_prepared,
                attempt,
                "gocode-attempt-0001",
                &profile,
            ))
            .await
            .expect("settled replay"),
        stream
    );
    assert_eq!(credential_calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.lock().expect("observations").len(), 1);
    assert!(adapter.next(&stream, StreamCursor::new(5)).await.is_err());
}

#[tokio::test]
async fn active_attempt_capacity_rejects_before_credential_or_network_effect() {
    let (adapter, observations, credential_calls) = adapter(
        Ok(sse(support::successful_sse())),
        Ok(b"fixture-key".to_vec()),
    );
    let profile = support::profile();
    let mut streams = Vec::new();
    for seed in 40_u8..48 {
        let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
        streams.push(
            adapter
                .dispatch(support::dispatch_request(
                    prepared,
                    DispatchAttemptId::from_bytes([seed; 16]),
                    &format!("gocode-active-attempt-{seed}"),
                    &profile,
                ))
                .await
                .expect("bounded active dispatch"),
        );
    }
    let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
    assert_eq!(
        adapter
            .dispatch(support::dispatch_request(
                prepared,
                DispatchAttemptId::from_bytes([48; 16]),
                "gocode-active-attempt-overflow",
                &profile,
            ))
            .await,
        Err(DispatchError::RejectedBeforeEffect(
            ProviderPreEffectRejection::AdapterRejected
        ))
    );
    assert_eq!(credential_calls.load(Ordering::SeqCst), 8);
    assert_eq!(observations.lock().expect("observations").len(), 8);

    for stream in streams {
        assert_eq!(
            adapter.cancel(CancelRequest::new(stream)).await.unwrap(),
            CancelDisposition::Requested
        );
    }
}

#[tokio::test]
async fn credential_missing_or_denied_is_proved_before_network_effect() {
    for (credential, rejection) in [
        (
            Err(OpenAiCredentialError::Missing),
            ProviderPreEffectRejection::CredentialUnavailable,
        ),
        (
            Err(OpenAiCredentialError::AccessDenied),
            ProviderPreEffectRejection::CredentialAccessDenied,
        ),
    ] {
        let (adapter, observations, calls) =
            adapter(Ok(sse(support::successful_sse())), credential);
        let profile = support::profile();
        let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
        let result = adapter
            .dispatch(support::dispatch_request(
                prepared,
                DispatchAttemptId::from_bytes([4; 16]),
                "gocode-attempt-credential",
                &profile,
            ))
            .await;
        assert_eq!(result, Err(DispatchError::RejectedBeforeEffect(rejection)));
        assert!(observations.lock().expect("observations").is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn transport_or_parser_failure_after_dispatch_is_maybe_dispatched_and_not_retried() {
    let (uncertain_adapter, observations, credential_calls) = adapter(
        Err(OpenAiTransportError::Unavailable),
        Ok(b"fixture-key".to_vec()),
    );
    let profile = support::profile();
    let prepared = uncertain_adapter
        .prepare(&support::call(&profile))
        .expect("prepare");
    let attempt = DispatchAttemptId::from_bytes([5; 16]);
    let request = support::dispatch_request(
        prepared.clone(),
        attempt,
        "gocode-attempt-uncertain",
        &profile,
    );
    assert_eq!(
        uncertain_adapter.dispatch(request).await,
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(
        uncertain_adapter
            .dispatch(support::dispatch_request(
                prepared,
                attempt,
                "gocode-attempt-uncertain",
                &profile,
            ))
            .await,
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(observations.lock().expect("observations").len(), 1);
    assert_eq!(
        uncertain_adapter
            .reconcile(ReconcileRequest::new(attempt))
            .await
            .expect("reconcile"),
        ReconciliationDisposition::Uncertain
    );

    for seed in 7_u8..14 {
        let prepared = uncertain_adapter
            .prepare(&support::call(&profile))
            .expect("prepare");
        assert_eq!(
            uncertain_adapter
                .dispatch(support::dispatch_request(
                    prepared,
                    DispatchAttemptId::from_bytes([seed; 16]),
                    &format!("gocode-attempt-uncertain-{seed}"),
                    &profile,
                ))
                .await,
            Err(DispatchError::MaybeDispatched)
        );
    }
    assert_eq!(observations.lock().expect("observations").len(), 8);
    assert_eq!(credential_calls.load(Ordering::SeqCst), 8);

    let prepared = uncertain_adapter
        .prepare(&support::call(&profile))
        .expect("prepare");
    assert_eq!(
        uncertain_adapter
            .dispatch(support::dispatch_request(
                prepared,
                DispatchAttemptId::from_bytes([14; 16]),
                "gocode-attempt-after-eight-uncertain",
                &profile,
            ))
            .await,
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(observations.lock().expect("observations").len(), 9);
    assert_eq!(credential_calls.load(Ordering::SeqCst), 9);

    let (parser_adapter, _, _) = adapter(
        Ok(sse(b"event: response.future\ndata: {}\n\n".to_vec())),
        Ok(b"fixture-key".to_vec()),
    );
    let prepared = parser_adapter
        .prepare(&support::call(&profile))
        .expect("prepare");
    assert_eq!(
        parser_adapter
            .dispatch(support::dispatch_request(
                prepared,
                DispatchAttemptId::from_bytes([6; 16]),
                "gocode-attempt-parser",
                &profile,
            ))
            .await,
        Err(DispatchError::MaybeDispatched)
    );

    assert_eq!(
        OpenAiTransportResponse::sse(vec![Vec::new(); OPENAI_MAX_TRANSPORT_CHUNKS + 1]),
        Err(OpenAiTransportError::StreamLimitExceeded)
    );
}

#[tokio::test]
async fn failed_incomplete_error_and_non_2xx_are_terminal_without_retry() {
    let branches = [
        sse(support::failed_sse()),
        sse(support::incomplete_sse()),
        sse(support::standalone_error_sse()),
        OpenAiTransportResponse::json_rejection(
            429,
            br#"{"error":{"message":"bounded raw remote diagnostic","type":"rate_limit_error"}}"#
                .to_vec(),
        )
        .expect("non-2xx response"),
    ];
    for (index, response) in branches.into_iter().enumerate() {
        let (adapter, _, _) = adapter(Ok(response), Ok(b"fixture-key".to_vec()));
        let profile = support::profile();
        let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
        let attempt = DispatchAttemptId::from_bytes([u8::try_from(20 + index).unwrap(); 16]);
        let stream = adapter
            .dispatch(support::dispatch_request(
                prepared,
                attempt,
                &format!("gocode-attempt-terminal-{index}"),
                &profile,
            ))
            .await
            .expect("terminal stream");
        assert_eq!(
            adapter
                .reconcile(ReconcileRequest::new(attempt))
                .await
                .expect("reconcile"),
            ReconciliationDisposition::Settled
        );
        assert!(adapter.next(&stream, StreamCursor::new(0)).await.is_ok());
    }
}

#[tokio::test]
async fn cancel_is_local_idempotent_and_does_not_claim_remote_settlement() {
    let (adapter, _, _) = adapter(
        Ok(sse(support::successful_sse())),
        Ok(b"fixture-key".to_vec()),
    );
    let profile = support::profile();
    let prepared = adapter.prepare(&support::call(&profile)).expect("prepare");
    let attempt = DispatchAttemptId::from_bytes([9; 16]);
    let stream = adapter
        .dispatch(support::dispatch_request(
            prepared,
            attempt,
            "gocode-attempt-cancel",
            &profile,
        ))
        .await
        .expect("dispatch");
    assert_eq!(
        adapter.cancel(CancelRequest::new(stream)).await.unwrap(),
        CancelDisposition::Requested
    );
    assert_eq!(
        adapter.cancel(CancelRequest::new(stream)).await.unwrap(),
        CancelDisposition::AlreadyRequested
    );
    assert!(adapter.next(&stream, StreamCursor::new(0)).await.is_err());
    assert_eq!(
        adapter
            .reconcile(ReconcileRequest::new(attempt))
            .await
            .expect("reconcile"),
        ReconciliationDisposition::Uncertain
    );
}
