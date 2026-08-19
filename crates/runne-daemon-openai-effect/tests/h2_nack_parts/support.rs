use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;

use runne_daemon_openai_effect::{
    FixtureRequestAuthenticator, effect_from_loopback_fixture, loopback_fixture_client,
    loopback_fixture_request_authenticator,
};
use runne_provider::{
    DispatchError, ReconcileRequest, ReconciliationDisposition,
};
use runne_provider_openai::{OpenAiResponsesTextProfile, OpenAiTransportPolicy};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy)]
enum Nack {
    RefusedStream,
    GoawayNoError,
}

struct NackServer {
    address: SocketAddr,
    certificate_der: Vec<u8>,
    attempts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<Result<(), ()>>,
}

impl NackServer {
    async fn start(nack: Nack, authenticator: FixtureRequestAuthenticator) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let (certificate_der, configuration) = tls_configuration();
        let attempts = Arc::new(AtomicUsize::new(0));
        let task_attempts = Arc::clone(&attempts);
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|_| ())?;
            let tls = TlsAcceptor::from(configuration)
                .accept(tcp)
                .await
                .map_err(|_| ())?;
            let mut connection = h2::server::handshake(tls)
                .await
                .map_err(|_| ())?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or(())?
                .map_err(|_| ())?;
            if request.method() != http::Method::POST
                || request.uri().path() != "/v1/responses"
                || !request
                    .headers()
                    .get(http::header::AUTHORIZATION)
                    .is_some_and(|value| authenticator.matches(value.as_bytes()))
            {
                return Err(());
            }
            task_attempts.fetch_add(1, Ordering::SeqCst);
            match nack {
                Nack::RefusedStream => respond.send_reset(h2::Reason::REFUSED_STREAM),
                Nack::GoawayNoError => connection.abrupt_shutdown(h2::Reason::NO_ERROR),
            }
            let same_connection = tokio::time::timeout(Duration::from_millis(300), connection.accept())
                .await;
            if matches!(same_connection, Ok(Some(Ok(_)))) {
                task_attempts.fetch_add(1, Ordering::SeqCst);
            }
            if tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_ok()
            {
                task_attempts.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        Self {
            address,
            certificate_der,
            attempts,
            task,
        }
    }

    async fn assert_one_attempt(self) {
        self.task.await.expect("NACK server task").expect("valid NACK fixture");
        assert_eq!(self.attempts.load(Ordering::SeqCst), 1);
    }
}

fn tls_configuration() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![SanType::DnsName(
        "api.openai.com".try_into().expect("DNS name"),
    )];
    let key = KeyPair::generate().expect("certificate key");
    let certificate = parameters.self_signed(&key).expect("certificate");
    let certificate_der = certificate.der().to_vec();
    let mut configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS version")
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .expect("TLS certificate");
    configuration.alpn_protocols = vec![b"h2".to_vec()];
    (certificate_der, Arc::new(configuration))
}

async fn assert_uncertain_single_effect(nack: Nack) {
    let profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .expect("exact profile");
    let policy = OpenAiTransportPolicy::for_profile(&profile).expect("exact transport policy");
    let server = NackServer::start(nack, loopback_fixture_request_authenticator()).await;
    let client = loopback_fixture_client(&policy, server.address, &server.certificate_der)
        .expect("production-shaped loopback client");
    let (effect, _) = effect_from_loopback_fixture(client).expect("fixture effect");
    let (request, receipt, credential) = durable_dispatch(&profile, effect.as_ref());
    let attempt_id = request.attempt_id();
    let ready = effect
        .stage_effect(request, credential)
        .await
        .expect("stage admitted effect");
    assert_eq!(
        effect.dispatch_effect(ready, receipt).await,
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(
        effect.reconcile(ReconcileRequest::new(attempt_id)).await,
        Ok(ReconciliationDisposition::Uncertain)
    );
    server.assert_one_attempt().await;
}
