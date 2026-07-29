use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_runtime_client::{
    CanonicalId, CommandIdentity, CreateConversationRequest, EXPECTED_BUNDLE_ID,
    GOLDEN_BUNDLE_HASH, GenerateTextRequest, HttpRuntimeClient, RuntimeApiErrorKind,
    RuntimeCredential, RuntimeProfile,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const CREATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
const SEND_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000004";
const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000005";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000006";
const USER_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000007";
const ASSISTANT_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000008";

fn compatible_profile_body() -> String {
    format!(
        r#"{{"profileId":"{EXPECTED_BUNDLE_ID}","schemaHash":"{GOLDEN_BUNDLE_HASH}","runtimeVersion":"0.1.0","capabilities":["conversation.create.v1","conversation.generate_text.v1","conversation.list_messages.v1"]}}"#
    )
}

#[derive(Debug)]
struct RecordedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

#[tokio::test]
async fn rejects_a_success_response_for_a_different_conversation() {
    let profile_body = compatible_profile_body();
    let mismatched_body = format!(
        r#"{{"conversationId":"{TASK_RUN_ID}","workspaceId":"{WORKSPACE_ID}","streamVersion":1,"committedAt":1753800000000}}"#
    );
    let (address, _) = serve_responses(vec![
        json_response("200 OK", &profile_body),
        json_response("202 Accepted", &mismatched_body),
    ])
    .await;
    let endpoint = gocode_runtime_client::RuntimeEndpoint::loopback(address).expect("loopback");
    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(2)).expect("client");
    let authenticated = client
        .authenticate(RuntimeCredential::from_bytes([0x2a; 32]))
        .await
        .expect("authenticate");
    let error = authenticated
        .create_conversation(CreateConversationRequest::new(
            CommandIdentity::new(
                CanonicalId::parse(CREATE_COMMAND_ID).expect("command id"),
                "create-conversation",
            )
            .expect("identity"),
            CanonicalId::parse(CONVERSATION_ID).expect("conversation id"),
            CanonicalId::parse(WORKSPACE_ID).expect("workspace id"),
        ))
        .await
        .expect_err("mismatched response");

    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
}

#[tokio::test]
async fn rejects_an_unknown_error_envelope_instead_of_trusting_only_http_status() {
    let profile_body = compatible_profile_body();
    let error_body = format!(
        r#"{{"code":"conversation_conflict","requestId":"{CREATE_COMMAND_ID}","unexpected":true}}"#
    );
    let (address, _) = serve_responses(vec![
        json_response("200 OK", &profile_body),
        json_response("409 Conflict", &error_body),
    ])
    .await;
    let endpoint = gocode_runtime_client::RuntimeEndpoint::loopback(address).expect("loopback");
    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(2)).expect("client");
    let authenticated = client
        .authenticate(RuntimeCredential::from_bytes([0x2a; 32]))
        .await
        .expect("authenticate");
    let error = authenticated
        .list_messages(CanonicalId::parse(CONVERSATION_ID).expect("conversation id"))
        .await
        .expect_err("unknown error field");

    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn rejects_a_profile_missing_one_required_conversation_capability() {
    let profile_body = format!(
        r#"{{"profileId":"{EXPECTED_BUNDLE_ID}","schemaHash":"{GOLDEN_BUNDLE_HASH}","runtimeVersion":"0.1.0","capabilities":["conversation.create.v1","conversation.generate_text.v1"]}}"#
    );
    let (address, _) = serve_responses(vec![json_response("200 OK", &profile_body)]).await;
    let endpoint = gocode_runtime_client::RuntimeEndpoint::loopback(address).expect("loopback");
    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(2)).expect("client");

    let Err(error) = client
        .authenticate(RuntimeCredential::from_bytes([0x2a; 32]))
        .await
    else {
        panic!("incomplete capability profile must fail closed");
    };

    assert_eq!(error.kind(), RuntimeApiErrorKind::Incompatible);
}

async fn serve_responses(responses: Vec<String>) -> (SocketAddr, Arc<Mutex<Vec<RecordedRequest>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test runtime");
    let address = listener.local_addr().expect("runtime address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    tokio::spawn(async move {
        for response in responses {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let request = read_request(&mut socket).await;
            recorded.lock().expect("record request").push(request);
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
    });
    (address, requests)
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let read = socket.read(&mut buffer).await.expect("read request");
        assert!(read > 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(bytes.len() <= 16 * 1024, "request headers are bounded");
    };
    let headers_text = String::from_utf8(bytes[..header_end].to_vec()).expect("UTF-8 headers");
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().expect("request line").to_owned();
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header");
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect::<Vec<_>>();
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| {
            value.parse::<usize>().expect("content length")
        });
    while bytes.len() < header_end + content_length {
        let read = socket.read(&mut buffer).await.expect("read request body");
        assert!(read > 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    let body = String::from_utf8(bytes[header_end..header_end + content_length].to_vec())
        .expect("UTF-8 body");
    RecordedRequest {
        request_line,
        headers,
        body,
    }
}

fn json_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn authenticated_client_executes_the_canonical_conversation_journey() {
    let profile_body = compatible_profile_body();
    let create_body = format!(
        r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","streamVersion":1,"committedAt":1753800000000}}"#
    );
    let send_body = format!(
        r#"{{"conversationId":"{CONVERSATION_ID}","taskRunId":"{TASK_RUN_ID}","attemptId":"{ATTEMPT_ID}","conversationStreamVersion":3,"taskRunStreamVersion":5,"userMessage":{{"messageId":"{USER_MESSAGE_ID}","role":"user","taskRunId":"{TASK_RUN_ID}","attemptId":"{ATTEMPT_ID}","text":"hello","committedAt":1753800000001}},"assistantMessage":{{"messageId":"{ASSISTANT_MESSAGE_ID}","role":"assistant","taskRunId":"{TASK_RUN_ID}","attemptId":"{ATTEMPT_ID}","text":"GOCODE local response: hello","committedAt":1753800000002}}}}"#
    );
    let messages_body = format!(
        r#"{{"conversationId":"{CONVERSATION_ID}","streamVersion":3,"messages":[{{"messageId":"{USER_MESSAGE_ID}","role":"user","taskRunId":"{TASK_RUN_ID}","attemptId":"{ATTEMPT_ID}","text":"hello","committedAt":1753800000001}},{{"messageId":"{ASSISTANT_MESSAGE_ID}","role":"assistant","taskRunId":"{TASK_RUN_ID}","attemptId":"{ATTEMPT_ID}","text":"GOCODE local response: hello","committedAt":1753800000002}}]}}"#
    );
    let (address, requests) = serve_responses(vec![
        json_response("200 OK", &profile_body),
        json_response("202 Accepted", &create_body),
        json_response("200 OK", &send_body),
        json_response("200 OK", &messages_body),
    ])
    .await;
    let endpoint = gocode_runtime_client::RuntimeEndpoint::loopback(address).expect("loopback");
    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(2)).expect("client");
    let credential = RuntimeCredential::from_bytes([0x2a; 32]);

    let authenticated = client.authenticate(credential).await.expect("authenticate");
    let conversation_id = CanonicalId::parse(CONVERSATION_ID).expect("conversation id");
    let workspace_id = CanonicalId::parse(WORKSPACE_ID).expect("workspace id");
    let created = authenticated
        .create_conversation(CreateConversationRequest::new(
            CommandIdentity::new(
                CanonicalId::parse(CREATE_COMMAND_ID).expect("command id"),
                "create-conversation",
            )
            .expect("identity"),
            conversation_id,
            workspace_id,
        ))
        .await
        .expect("create conversation");
    assert_eq!(created.conversation_id, conversation_id);
    assert_eq!(created.workspace_id, workspace_id);
    assert_eq!(created.stream_version, 1);

    let generated = authenticated
        .generate_text(
            GenerateTextRequest::new(
                CommandIdentity::new(
                    CanonicalId::parse(SEND_COMMAND_ID).expect("command id"),
                    "send-message",
                )
                .expect("identity"),
                conversation_id,
                1,
                "hello",
            )
            .expect("text request"),
        )
        .await
        .expect("generate text");
    assert_eq!(
        generated.assistant_message.text,
        "GOCODE local response: hello"
    );
    assert_eq!(generated.conversation_stream_version, 3);
    assert_eq!(generated.task_run_stream_version, 5);

    let snapshot = authenticated
        .list_messages(conversation_id)
        .await
        .expect("list messages");
    assert_eq!(snapshot.stream_version, 3);
    assert_eq!(snapshot.messages.len(), 2);
    assert_eq!(snapshot.messages[0].text, "hello");
    assert_eq!(snapshot.messages[1].text, "GOCODE local response: hello");

    let requests = requests.lock().expect("read requests");
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].request_line, "GET /v1/runtime/profile HTTP/1.1");
    assert_eq!(requests[1].request_line, "POST /v1/conversations HTTP/1.1");
    assert_eq!(
        requests[2].request_line,
        format!("POST /v1/conversations/{CONVERSATION_ID}/messages HTTP/1.1")
    );
    assert_eq!(
        requests[3].request_line,
        format!("GET /v1/conversations/{CONVERSATION_ID}/messages HTTP/1.1")
    );
    for request in requests.iter() {
        let expected_authorization = format!("Bearer {}", "2a".repeat(32));
        assert!(
            request.headers.iter().any(|(name, value)| {
                name == "authorization" && value == &expected_authorization
            }),
            "every protected request must carry the host-owned credential: {:?}",
            request.headers
        );
    }
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value == "application/json")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[1].body).expect("create JSON"),
        serde_json::json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        })
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[2].body).expect("send JSON"),
        serde_json::json!({
            "expectedVersion": 1,
            "text": "hello",
        })
    );
    assert!(
        requests[1]
            .headers
            .iter()
            .any(|(name, value)| { name == "x-command-id" && value == CREATE_COMMAND_ID })
    );
    assert!(
        requests[1]
            .headers
            .iter()
            .any(|(name, value)| { name == "idempotency-key" && value == "create-conversation" })
    );
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|(name, value)| { name == "x-command-id" && value == SEND_COMMAND_ID })
    );
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|(name, value)| name == "idempotency-key" && value == "send-message")
    );
    drop(requests);
}
