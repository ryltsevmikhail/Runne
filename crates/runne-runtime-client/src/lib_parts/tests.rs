use super::*;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serve_once(response: &'static [u8]) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept health request");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 512];
        while !request.ends_with(b"\r\n\r\n") {
            let read = socket.read(&mut chunk).await.expect("read health request");
            assert!(read > 0, "health request ended before its headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(
                request.len() <= 4 * 1024,
                "health request headers too large"
            );
        }
        socket
            .write_all(response)
            .await
            .expect("write health response");
    });
    Ok(address)
}

#[test]
fn runtime_endpoint_accepts_only_loopback_addresses() {
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123);
    assert_eq!(
        RuntimeEndpoint::loopback(loopback)
            .expect("loopback endpoint")
            .address(),
        loopback
    );

    let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 43123);
    assert_eq!(
        RuntimeEndpoint::loopback(external),
        Err(RuntimeTransportError::EndpointNotLoopback)
    );
}

#[test]
fn runtime_profile_accepts_only_the_exact_bundle_identity() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123);
    let endpoint = RuntimeEndpoint::loopback(address).expect("endpoint");

    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("validated profile");
    assert_eq!(profile.endpoint().address(), address);

    assert_eq!(
        RuntimeProfile::validate(endpoint, "runne-ui-client/2", GOLDEN_BUNDLE_HASH),
        Err(RuntimeProfileError::ProfileMismatch)
    );
    assert_eq!(
        RuntimeProfile::validate(
            endpoint,
            EXPECTED_BUNDLE_ID,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        Err(RuntimeProfileError::SchemaHashMismatch)
    );
}

#[test]
fn health_transport_disables_system_proxies() {
    let endpoint =
        RuntimeEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123))
            .expect("endpoint");
    let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
        .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

    assert!(!format!("{:?}", client.client).contains("proxies"));
}

#[tokio::test]
async fn health_transport_reads_the_bounded_loopback_response() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33\r\nConnection: close\r\n\r\n{\"status\":\"ok\",\"version\":\"0.1.0\"}";
    let address = serve_once(response).await.expect("health server");
    let profile = RuntimeProfile::validate(
        RuntimeEndpoint::loopback(address).expect("endpoint"),
        EXPECTED_BUNDLE_ID,
        GOLDEN_BUNDLE_HASH,
    )
    .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

    assert_eq!(
        client.probe_health().await.expect("probe health"),
        RuntimeHealth::Ready {
            version: "0.1.0".to_owned(),
        }
    );
}

#[tokio::test]
async fn health_transport_rejects_redirects() {
    let response =
        b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n";
    let address = serve_once(response).await.expect("redirect server");
    let profile = RuntimeProfile::validate(
        RuntimeEndpoint::loopback(address).expect("endpoint"),
        EXPECTED_BUNDLE_ID,
        GOLDEN_BUNDLE_HASH,
    )
    .expect("profile");
    let client = HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

    assert_eq!(
        client.probe_health().await,
        Err(RuntimeTransportError::UnexpectedHttpStatus)
    );
}

#[test]
fn health_payload_maps_only_the_published_runtime_states() {
    assert_eq!(
        RuntimeHealth::parse(200, br#"{"status":"ok","version":"0.1.0"}"#).expect("ready health"),
        RuntimeHealth::Ready {
            version: "0.1.0".to_owned(),
        }
    );
    assert_eq!(
        RuntimeHealth::parse(200, br#"{"status":"degraded","version":"0.1.0"}"#)
            .expect("degraded health"),
        RuntimeHealth::RecoveryBlocked {
            version: "0.1.0".to_owned(),
        }
    );
    assert_eq!(
        RuntimeHealth::parse(503, br#"{"status":"shutting_down","version":"0.1.0"}"#,)
            .expect("shutdown health"),
        RuntimeHealth::ShuttingDown {
            version: "0.1.0".to_owned(),
        }
    );
}

#[test]
fn health_payload_fails_closed_on_unknown_state_or_status_mismatch() {
    assert_eq!(
        RuntimeHealth::parse(200, br#"{"status":"future","version":"0.1.0"}"#),
        Err(RuntimeHealthError::UnknownStatus)
    );
    assert_eq!(
        RuntimeHealth::parse(503, br#"{"status":"ok","version":"0.1.0"}"#),
        Err(RuntimeHealthError::StatusCodeMismatch)
    );
    assert_eq!(
        RuntimeHealth::parse(
            200,
            br#"{"status":"ok","version":"0.1.0","token":"secret"}"#
        ),
        Err(RuntimeHealthError::InvalidPayload)
    );
}

#[test]
fn connection_state_defaults_to_unconfigured_and_only_live_allows_mutations() {
    assert_eq!(
        RuntimeConnectionState::default(),
        RuntimeConnectionState::Unconfigured
    );
    assert!(!RuntimeConnectionState::Unconfigured.allows_mutations());
    assert!(!RuntimeConnectionState::Reconciling.allows_mutations());
    assert!(RuntimeConnectionState::Live.allows_mutations());
}

#[test]
fn health_contract_evidence_commit_is_valid_hex() {
    assert_eq!(HEALTH_CONTRACT_EVIDENCE_COMMIT.len(), 40);
    assert!(
        HEALTH_CONTRACT_EVIDENCE_COMMIT
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn golden_hash_is_valid_hex() {
    assert_eq!(GOLDEN_BUNDLE_HASH.len(), 64);
    assert!(GOLDEN_BUNDLE_HASH.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn bundle_id_is_expected() {
    assert_eq!(EXPECTED_BUNDLE_ID, "gocode-ui-client/3");
}

#[test]
fn supported_capability_profiles_are_exactly_ordered() {
    assert_eq!(
        REQUIRED_RUNTIME_CAPABILITIES,
        [
            "conversation.create.v1",
            "conversation.generate_text.v1",
            "conversation.list_messages.v1",
            "task_run.submit.v1",
            "task_run.submit.v2",
            "task_run.get.v1",
            "task_run.cancel.v1",
            "task_run.successor.v1",
            "replay.aggregate.open.v1",
            "replay.aggregate.retention_baseline.v1",
            "replay.aggregate.retention_baseline_resume.v2",
            "replay.aggregate.read_page.v1",
            "replay.aggregate.acknowledge.v1",
            "replay.aggregate.complete_catch_up.v1",
            "replay.aggregate.continue_live.v1",
            "replay.aggregate.sse.v1",
            "runtime.operational-telemetry.v1",
            "approval.control.v1",
            "project.list.v1",
            "project.get.v1",
            "project.create.v1",
            "project.archive.v1",
            "project.rename.v1",
            "project.restore.v1",
            "project.delete.v1",
            "workspace.list.v1",
            "workspace.get.v1",
            "workspace.create.v1",
            "workspace.open.v1",
        ]
    );
    let mut protected = REQUIRED_RUNTIME_CAPABILITIES.to_vec();
    protected.push("workspace.bind_root.v3");
    protected.push("workspace.files.read.v1");
    protected.push("workspace.changes.read.v1");
    protected.push("workspace.editor.open.v1");
    assert_eq!(PROTECTED_RUNTIME_CAPABILITIES, protected);
}
