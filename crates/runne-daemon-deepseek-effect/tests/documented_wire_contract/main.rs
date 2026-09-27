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
#[cfg(feature = "linux-native-enrollment-qualification")]
use std::sync::Mutex;

#[cfg(feature = "linux-native-enrollment-qualification")]
#[derive(Default)]
struct RecordingObserver(Mutex<Vec<runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic>>);

#[cfg(feature = "linux-native-enrollment-qualification")]
impl runne_daemon_deepseek_effect::DeepSeekEffectObserver for RecordingObserver {
    fn observe(&self, diagnostic: runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic) {
        self.0.lock().expect("diagnostics lock").push(diagnostic);
    }
}

include!("dispatch.rs");

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
                    "data: {\"choices\":[{}],\"marker\":\"BODY_MARKER_NOT_FOR_DIAGNOSTICS\"}\n\ndata: [DONE]\n\n".to_owned(),
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

#[tokio::test]
async fn adapter_sends_documented_request_and_decodes_documented_sse() {
    let server = DocumentedServer::start(WireResponse::Sse(documented_sse())).await;
    let (captured, events, authenticator, _diagnostics) = dispatch_on(server).await;
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
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(_diagnostics.contains(
        &runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic::ResponseStatus(
            runne_daemon_deepseek_effect::DeepSeekHttpStatusClass::Ok200
        )
    ));
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(
        _diagnostics.contains(&runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic::Decoded)
    );
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(
        _diagnostics
            .contains(&runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic::StreamStored)
    );
}

#[tokio::test]
async fn adapter_closes_documented_json_rejection_without_leaking_the_credential() {
    let rejection = r#"{"error":{"message":"Authentication Fails; wrong API key BODY_MARKER_NOT_FOR_DIAGNOSTICS","type":"authentication_error"}}"#.to_owned();
    let server = DocumentedServer::start(WireResponse::JsonRejection(401, rejection)).await;
    let (captured, events, authenticator, _diagnostics) = dispatch_on(server).await;
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
    #[cfg(feature = "linux-native-enrollment-qualification")]
    let diagnostic_text = format!("{_diagnostics:?}");
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(diagnostic_text.contains("Unauthorized401"));
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(!diagnostic_text.contains("BODY_MARKER_NOT_FOR_DIAGNOSTICS"));
}

include!("diagnostic_failure.rs");

#[tokio::test]
async fn adapter_decodes_documented_sse_without_in_progress_wrapper() {
    let server =
        DocumentedServer::start(WireResponse::Sse(documented_sse_without_in_progress())).await;
    let (captured, events, authenticator, _diagnostics) = dispatch_on(server).await;
    let events = events.expect("documented dispatch without in_progress");

    assert_eq!(captured.path, "/responses");
    assert!(authenticator.matches(captured.authorization.as_bytes()));
    assert_eq!(events.len(), 5);
    #[cfg(feature = "linux-native-enrollment-qualification")]
    assert!(
        _diagnostics
            .contains(&runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic::StreamStored)
    );
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
