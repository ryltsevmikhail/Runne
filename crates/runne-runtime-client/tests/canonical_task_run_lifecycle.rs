//! X2 `canonical_task_run_lifecycle` conformance test (plan 14 Task X2,
//! Step 2). Drives the typed public client through the exact client-facing
//! `TaskRun` surface — submit → get → list → replay → cancel — against raw
//! wire fixtures, and pins the closed shape of that surface:
//!
//! - submit uses authenticated command identity and accepts only the exact
//!   `submitted` acknowledgement at stream version 2;
//! - a repeated identical identity resends the same payload (the runtime
//!   replays the stored receipt server-side);
//! - get/list decode canonical snapshots only;
//! - replay delivers `taskRun.created` + `taskRun.queued` as typed timeline
//!   events (no Created-only observation without the Queued counterpart);
//! - cancel requires the exact `cancellation_requested` transition;
//! - the client capability profile contains submit/get/cancel and never
//!   queue/admit/start/complete (those stay runtime-owned; the compile-time
//!   counterpart is that no such methods exist on `AuthenticatedRuntimeClient`).
//!
//! Runtime-owned transitions are never mounted on the client contour
//! (`crates/runne-http/src/task_runs/canonical.rs`); this file proves the
//! client side of the same contract.

use std::net::Ipv4Addr;

use runne_runtime_client::{
    CancelTaskRunRequest, CanonicalId, CommandIdentity, REQUIRED_RUNTIME_CAPABILITIES,
    ReplayAggregateKind, ReplayScope, RuntimeApiErrorKind, RuntimeSessionInfo,
    SubmitTaskRunRequest, TaskRunState, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-0000000002a0";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-0000000002a1";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-0000000002a2";
const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000002a3";
const CANCEL_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-0000000002a4";
const REPLAY_BINDING: &str = "018f2e3a7000700080000000000002a5";

fn task_run_id() -> CanonicalId {
    CanonicalId::parse(TASK_RUN_ID).expect("task run ID")
}

fn conversation_id() -> CanonicalId {
    CanonicalId::parse(CONVERSATION_ID).expect("conversation ID")
}

fn workspace_id() -> CanonicalId {
    CanonicalId::parse(WORKSPACE_ID).expect("workspace ID")
}

fn identity(command_id: &str, key: &str) -> CommandIdentity {
    CommandIdentity::new(CanonicalId::parse(command_id).expect("command ID"), key)
        .expect("identity")
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authority_id: "authority".to_owned(),
        principal_id: "local-owner".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
        capability_digest: "digest".to_owned(),
    }
}

fn response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn submit_ack_body(task_run_id: &str, version: u64, transition: &str) -> String {
    format!(
        "{{\"taskRunId\":\"{task_run_id}\",\"streamVersion\":{version},\"transition\":\"{transition}\",\"attemptId\":null,\"terminalResult\":null}}"
    )
}

fn snapshot_body(state: &str, version: u64, with_terminal: bool) -> String {
    let terminal = if with_terminal {
        ",\"terminalResult\":{\"type\":\"success\"}"
    } else {
        ",\"terminalResult\":null"
    };
    format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"{state}\",\"streamVersion\":{version},\"activeAttemptId\":null{terminal}}}"
    )
}

/// A loopback raw fixture server. Binds immediately and accepts each expected
/// request in a background task, so the caller never blocks on accept while
/// constructing the client (which would deadlock the current-thread runtime).
struct RawServer {
    origin: String,
    task: tokio::task::JoinHandle<Vec<String>>,
}

impl RawServer {
    fn new(listener: TcpListener, responses: Vec<String>) -> Self {
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.expect("read");
                    assert_ne!(read, 0, "request headers");
                    request.extend_from_slice(&buffer[..read]);
                }
                requests.push(String::from_utf8(request).expect("request UTF-8"));
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response");
            }
            requests
        });
        Self { origin, task }
    }

    fn origin(&self) -> &str {
        &self.origin
    }

    async fn finish(self) -> Vec<String> {
        self.task.await.expect("server task")
    }
}

/// Convenience wrapper binding a fresh loopback fixture server.
async fn serve(responses: Vec<String>) -> RawServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    RawServer::new(listener, responses)
}

include!("canonical_task_run_lifecycle_parts/lifecycle.rs");
include!("canonical_task_run_lifecycle_parts/surface.rs");
include!("canonical_task_run_lifecycle_parts/cursor.rs");
