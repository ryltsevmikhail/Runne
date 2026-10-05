use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use runne_daemon_openai_effect::FixtureRequestAuthenticator;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::fixed_response::{
    D2_TOOL_PROPOSAL_RESPONSE, SSE_RESPONSE, d2_tool_loop_response, d2_tool_scenario_response,
};
use super::request_validation::{FixtureRequestKind, matches_expected_request, request_length_for};
mod io;
use super::t1_scan_receipt::write_t1_scan_receipt;
use io::{hold_for_kill_boundary, increment_named_count, increment_request_count, read_request};
#[path = "tls_sse_server/d2_hold.rs"]
mod d2_hold;
#[cfg(all(target_os = "linux", feature = "test-support", not(test)))]
#[path = "tls_sse_server/d2_scenario.rs"]
mod d2_scenario;

/// One-use loopback HTTPS endpoint serving the fixture's fixed SSE response.
pub struct TlsSseServer {
    address: SocketAddr,
    certificate_der: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl TlsSseServer {
    pub(super) async fn start(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        request_kind: FixtureRequestKind,
    ) -> Result<Self, ()> {
        Self::start_with_scan(
            runtime_root,
            authenticator,
            request_kind,
            false,
            false,
            None,
        )
        .await
    }

    #[cfg(all(target_os = "linux", feature = "test-support", not(test)))]
    pub(super) async fn start_t1(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        drop_response: bool,
    ) -> Result<Self, ()> {
        let d2_scenario = d2_scenario::selected(runtime_root)?;
        let request_kind = if d2_scenario.is_some() {
            FixtureRequestKind::D2ToolLoop
        } else if std::env::var_os("RUNNE_TEST_D2_TOOL_PROPOSAL").is_some() {
            FixtureRequestKind::D2ToolProposal
        } else {
            FixtureRequestKind::ServicePointOfUse
        };
        Self::start_with_scan(
            runtime_root,
            authenticator,
            request_kind,
            true,
            drop_response,
            d2_scenario,
        )
        .await
    }

    async fn start_with_scan(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        request_kind: FixtureRequestKind,
        scan_wire: bool,
        drop_response: bool,
        d2_scenario: Option<String>,
    ) -> Result<Self, ()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let address = listener.local_addr().map_err(|_| ())?;
        let (certificate_der, config) = tls_config()?;
        let count_path = runtime_root.join("fixture-provider-request-count");
        let scan_receipt_path = runtime_root.join("fixture-provider-wire-scan-receipt.json");
        let task = tokio::spawn(async move {
            for request_index in 0..3 {
                let Some(request_kind) = request_kind.for_request(request_index) else {
                    return;
                };
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                if scan_wire
                    && increment_named_count(&count_path, "fixture-provider-connection-count")
                        .is_err()
                {
                    return;
                }
                let Ok(mut stream) = TlsAcceptor::from(Arc::clone(&config)).accept(stream).await
                else {
                    return;
                };
                let Ok(request) = read_request(&mut stream, request_kind).await else {
                    return;
                };
                if (!scan_wire
                    && increment_named_count(&count_path, "fixture-provider-connection-count")
                        .is_err())
                    || !matches_expected_request(&request, &authenticator, request_kind)
                    || increment_request_count(&count_path).is_err()
                {
                    return;
                }
                // D1.6 kill matrix: hold the request in flight (b4) after the
                // provider has received it but before any response byte returns.
                hold_for_kill_boundary("b4_dispatch_in_flight").await;
                let response_body = if d2_scenario.as_deref() == Some("budget-exhausted")
                    && matches!(request_kind, FixtureRequestKind::D2ToolLoopRound2)
                {
                    D2_TOOL_PROPOSAL_RESPONSE
                        .replace("resp_d2_read", "resp_d2_budget")
                        .replace("fc_d2_read", "fc_d2_budget")
                        .replace("call_d2_read", "call_d2_budget")
                } else if matches!(request_kind, FixtureRequestKind::D2ToolLoopRound0) {
                    d2_scenario
                        .as_deref()
                        .and_then(d2_tool_scenario_response)
                        .or_else(|| d2_tool_loop_response(0).map(str::to_owned))
                        .unwrap_or_else(|| SSE_RESPONSE.to_owned())
                } else {
                    match request_kind {
                        FixtureRequestKind::D2ToolProposal => D2_TOOL_PROPOSAL_RESPONSE.to_owned(),
                        FixtureRequestKind::D2ToolLoopRound0 => d2_tool_loop_response(0)
                            .expect("fixture round zero response")
                            .to_owned(),
                        FixtureRequestKind::D2ToolLoopRound1 => d2_tool_loop_response(1)
                            .expect("fixture round one response")
                            .to_owned(),
                        FixtureRequestKind::D2ToolLoopRound2 => d2_tool_loop_response(2)
                            .expect("fixture round two response")
                            .to_owned(),
                        _ => SSE_RESPONSE.to_owned(),
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                if drop_response {
                    if scan_wire
                        && write_t1_scan_receipt(&scan_receipt_path, &request, &[], false).is_err()
                    {
                        return;
                    }
                    return;
                }
                let mut response_written = 0;
                if matches!(
                    d2_scenario.as_deref(),
                    Some("cancel-final-response" | "stale-final-target")
                ) && request_index == 2
                {
                    let Ok(prefix) =
                        d2_hold::hold_final_stop(&mut stream, response.as_bytes()).await
                    else {
                        return;
                    };
                    response_written = prefix;
                }
                // D1.6 kill matrix: serve the stream in two chunks so the b6
                // boundary can hold the daemon BETWEEN received stream events —
                // a single full-write would let the client complete first.
                let first_chunk = response.len() / 2;
                while response_written < response.len() {
                    if response_written > 0 {
                        hold_for_kill_boundary("b6_between_stream_events").await;
                    }
                    let remaining = &response.as_bytes()[response_written..];
                    let limit = if response_written == 0 && first_chunk > 0 {
                        first_chunk
                    } else {
                        remaining.len()
                    };
                    match stream.write(&remaining[..limit]).await {
                        Ok(0) | Err(_) => break,
                        Ok(written) => response_written += written,
                    }
                }
                if scan_wire
                    && write_t1_scan_receipt(
                        &scan_receipt_path,
                        &request,
                        &response.as_bytes()[..response_written],
                        response_written == response.len(),
                    )
                    .is_err()
                {
                    return;
                }
                let _ = stream.shutdown().await;
            }
        });
        Ok(Self {
            address,
            certificate_der,
            task,
        })
    }

    #[allow(clippy::result_unit_err)]
    pub fn client(&self) -> Result<reqwest::Client, ()> {
        loopback_client(self.address, &self.certificate_der)
    }
}

impl Drop for TlsSseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tls_config() -> Result<(Vec<u8>, Arc<rustls::ServerConfig>), ()> {
    let mut params = CertificateParams::new(Vec::new()).map_err(|_| ())?;
    params.subject_alt_names = vec![SanType::DnsName(
        "api.openai.com".try_into().map_err(|_| ())?,
    )];
    let key = KeyPair::generate().map_err(|_| ())?;
    let certificate = params.self_signed(&key).map_err(|_| ())?;
    let certificate_der = certificate.der().to_vec();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| ())?
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .map_err(|_| ())?;
    Ok((certificate_der, Arc::new(config)))
}

/// Builds the only fixture client route; it rejects every non-loopback target.
#[allow(clippy::result_unit_err)]
pub fn loopback_client(address: SocketAddr, certificate_der: &[u8]) -> Result<reqwest::Client, ()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(());
    }
    let certificate = reqwest::Certificate::from_der(certificate_der).map_err(|_| ())?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .default_headers(reqwest::header::HeaderMap::new())
        .resolve("api.openai.com", address)
        .add_root_certificate(certificate)
        .build()
        .map_err(|_| ())
}
