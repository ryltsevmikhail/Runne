#![allow(dead_code)]

mod fixture;

include!("../h2_nack_parts/support.rs");
include!("../h2_nack_parts/durable_receipt.rs");

use fixture::{WireResponse, documented_sse, documented_sse_without_in_progress};
use runne_provider::{
    ProviderFinishReason, ProviderPort, ProviderStreamEventKind, ProviderTerminalDisposition,
    StreamCursor, StreamError,
};
use serde_json::Value;

struct Captured {
    path: String,
    method: String,
    authorization: String,
    content_type: Option<String>,
    request_id: Option<String>,
    body: Vec<u8>,
}

struct DocumentedServer {
    address: std::net::SocketAddr,
    certificate_der: Vec<u8>,
    task: tokio::task::JoinHandle<Captured>,
}

impl DocumentedServer {
    async fn start(response: WireResponse) -> Self {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let (certificate_der, configuration) = tls_configuration();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("loopback accept");
            let tls = tokio_rustls::TlsAcceptor::from(configuration)
                .accept(tcp)
                .await
                .expect("loopback TLS");
            let mut connection = h2::server::handshake(tls).await.expect("h2 handshake");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("h2 request")
                .expect("h2 request ok");
            let (parts, mut body) = request.into_parts();
            let mut captured_body = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.expect("h2 body chunk");
                let _ = body.flow_control().release_capacity(chunk.len());
                captured_body.extend_from_slice(&chunk);
            }
            let headers = &parts.headers;
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            };
            let captured = Captured {
                path: parts.uri.path().to_owned(),
                method: parts.method.as_str().to_owned(),
                authorization: header("authorization").unwrap_or_default(),
                content_type: header("content-type"),
                request_id: header("x-client-request-id"),
                body: captured_body,
            };
            let (status, content_type, payload) = match response {
                WireResponse::Sse(body) => (200u16, "text/event-stream", body),
                WireResponse::JsonRejection(status, body) => (status, "application/json", body),
                WireResponse::ChatDone => (
                    200,
                    "text/event-stream",
                    "data: {\"choices\":[{}]}\n\ndata: [DONE]\n\n".to_owned(),
                ),
            };
            let wire = http::Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(())
                .expect("h2 response");
            let mut send = respond.send_response(wire, false).expect("h2 respond");
            send.send_data(bytes::Bytes::from_owner(payload.into_bytes()), true)
                .expect("h2 response body");
            // Hold the h2 connection so the client completes the exchange
            // instead of observing an abrupt TLS close.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while connection
                    .accept()
                    .await
                    .is_some_and(|result| result.is_ok())
                {}
            })
            .await;
            captured
        });
        Self {
            address,
            certificate_der,
            task,
        }
    }
}

fn profile() -> DeepSeekResponsesTextProfile {
    DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .expect("exact profile")
}

async fn dispatch_on(
    server: DocumentedServer,
) -> (
    Captured,
    Result<Vec<runne_provider::ProviderStreamEvent>, DispatchError>,
    runne_daemon_deepseek_effect::FixtureRequestAuthenticator,
) {
    let profile = profile();
    let policy = DeepSeekTransportPolicy::for_profile(&profile).expect("exact policy");
    let client = loopback_fixture_client(&policy, server.address, &server.certificate_der)
        .expect("loopback client");
    let (effect, authenticator) = effect_from_loopback_fixture(client).expect("fixture effect");
    let (request, receipt, credential) = durable_dispatch(&profile, effect.as_ref());
    let ready = effect
        .stage_effect(request, credential)
        .await
        .expect("stage admitted effect");
    let dispatch = effect.dispatch_effect(ready, receipt).await;
    let events = match dispatch {
        Ok(stream) => {
            let mut events = Vec::new();
            let mut cursor = StreamCursor::new(0);
            loop {
                match ProviderPort::next(effect.as_ref(), &stream, cursor).await {
                    Ok(item) => {
                        events.push(item.event().clone());
                        cursor = StreamCursor::new(cursor.sequence() + 1);
                    }
                    Err(StreamError::Closed) => break,
                    Err(error) => panic!("unexpected stream error: {error}"),
                }
            }
            Ok(events)
        }
        Err(error) => Err(error),
    };
    (
        server.task.await.expect("server task"),
        events,
        authenticator,
    )
}

#[tokio::test]
async fn adapter_sends_documented_request_and_decodes_documented_sse() {
    let server = DocumentedServer::start(WireResponse::Sse(documented_sse())).await;
    let (captured, events, authenticator) = dispatch_on(server).await;
    let events = events.expect("documented dispatch");

    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/responses");
    assert_eq!(captured.content_type.as_deref(), Some("application/json"));
    assert_eq!(captured.request_id.as_deref(), Some("h2-nack-one-effect"));
    assert!(authenticator.matches(captured.authorization.as_bytes()));
    let body: Value = serde_json::from_slice(&captured.body).unwrap();
    assert_eq!(body["model"], "deepseek-flash");
    for unsupported in ["service_tier", "background", "store"] {
        assert!(
            body.get(unsupported).is_none(),
            "{unsupported} must not be sent"
        );
    }
    assert_eq!(body["input"][0]["content"][0]["text"], "hello");
    assert_eq!(body["stream"], true);

    assert_eq!(events.len(), 5);
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    assert_eq!(
        events[1].kind(),
        &ProviderStreamEventKind::TextDelta {
            text: "Привет, ".to_owned()
        }
    );
    let ProviderStreamEventKind::Usage { usage } = events[3].kind() else {
        panic!("expected usage");
    };
    assert_eq!(usage.input_tokens(), 11);
    assert_eq!(usage.cached_input_tokens(), 3);
    assert_eq!(usage.output_tokens(), 4);
    assert_eq!(
        events[4].kind(),
        &ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop
        }
    );
    let evidence = format!("{events:?}");
    assert!(!evidence.contains("fixture-credential"));
    assert!(!evidence.contains("Bearer "));
}

#[tokio::test]
async fn adapter_closes_documented_json_rejection_without_leaking_the_credential() {
    let rejection = r#"{"error":{"message":"Authentication Fails; wrong API key","type":"authentication_error"}}"#.to_owned();
    let server = DocumentedServer::start(WireResponse::JsonRejection(401, rejection)).await;
    let (captured, events, authenticator) = dispatch_on(server).await;
    let events = events.expect("documented rejection dispatch");

    assert_eq!(captured.path, "/responses");
    assert!(authenticator.matches(captured.authorization.as_bytes()));
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    assert!(matches!(
        events[1].kind(),
        ProviderStreamEventKind::UsageUnavailable
    ));
    assert_eq!(
        events[2].kind(),
        &ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error
        }
    );
    let evidence = format!("{events:?}");
    assert!(!evidence.contains("fixture-credential"));
    assert!(!evidence.contains("Bearer "));
}

#[tokio::test]
async fn adapter_fails_closed_on_chat_done_terminal_frame() {
    let server = DocumentedServer::start(WireResponse::ChatDone).await;
    let (_, events, _) = dispatch_on(server).await;
    assert_eq!(events, Err(DispatchError::MaybeDispatched));
}

#[tokio::test]
async fn adapter_decodes_documented_sse_without_in_progress_wrapper() {
    let server =
        DocumentedServer::start(WireResponse::Sse(documented_sse_without_in_progress())).await;
    let (captured, events, authenticator) = dispatch_on(server).await;
    let events = events.expect("documented dispatch without in_progress");

    assert_eq!(captured.path, "/responses");
    assert!(authenticator.matches(captured.authorization.as_bytes()));
    assert_eq!(events.len(), 5);
    assert!(matches!(events[0].kind(), ProviderStreamEventKind::Started));
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event.kind() {
                ProviderStreamEventKind::TextDelta { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>(),
        "Привет, world"
    );
    let ProviderStreamEventKind::Usage { usage } = events[3].kind() else {
        panic!("expected usage");
    };
    assert_eq!(usage.total_tokens(), 15);
    assert_eq!(
        events[4].kind(),
        &ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop
        }
    );
}
