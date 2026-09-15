use super::*;
use crate::{QuotaRefreshResponse, QuotaRefreshTransportError};
use runne_provider::{
    BeginCredentialVerification, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialReadinessRevision, CredentialVerificationKind, CredentialVerifierRevision,
    CredentialVersionRef, ProviderId,
};
use runne_provider_quota::{
    QuotaAuthHeaderKind, QuotaAvailability, QuotaDecision, QuotaIdentity, QuotaRefreshStatus,
    QuotaRequestDescriptor, QuotaStateStore,
};
use runne_secure_store::{
    ProviderCredentialMaterial, ProviderCredentialVerificationMaterializer, SecureStoreError,
};
use std::{
    collections::VecDeque,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

struct FakeMaterializer {
    calls: AtomicUsize,
    denied: bool,
}

impl ProviderCredentialVerificationMaterializer for FakeMaterializer {
    fn materialize_for_verification(
        &self,
        _: &runne_provider::CredentialVerificationCapability,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.denied {
            Err(SecureStoreError::CredentialAccessDenied)
        } else {
            ProviderCredentialMaterial::new(b"fixture-token".to_vec())
        }
    }
}

struct FakeTransport {
    calls: AtomicUsize,
    endpoint: Mutex<Option<String>>,
    auth: Mutex<Option<QuotaAuthHeaderKind>>,
    responses: Mutex<VecDeque<QuotaRefreshResponse>>,
}

impl QuotaRefreshTransport for FakeTransport {
    fn get<'a>(
        &'a self,
        endpoint: String,
        auth: QuotaAuthHeaderKind,
        token: Zeroizing<Vec<u8>>,
        _: std::time::Duration,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<QuotaRefreshResponse, QuotaRefreshTransportError>,
                > + Send
                + 'a,
        >,
    > {
        self.calls.fetch_add(1, Ordering::Relaxed);
        *self.endpoint.lock().unwrap() = Some(endpoint);
        *self.auth.lock().unwrap() = Some(auth);
        assert_eq!(&*token, b"fixture-token");
        let response = self.responses.lock().unwrap().pop_front();
        Box::pin(async move { response.ok_or(QuotaRefreshTransportError) })
    }
}

fn capability(
    provider_name: &str,
    version: u64,
    expiry: i64,
    binding_digest: [u8; 32],
) -> CredentialVerificationCapability {
    let provider = ProviderId::new(provider_name).unwrap();
    let begin = BeginCredentialVerification::new(
        CredentialOperationId::from_bytes([version as u8; 16]).unwrap(),
        None,
        provider.clone(),
        CredentialVerificationKind::Remote,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        CredentialBindingDigest::from_measured([1; 32]).unwrap(),
        CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        CredentialVerifierRevision::new(1).unwrap(),
        1,
        expiry,
    )
    .unwrap();
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let lease = store.issue_credential_verification_lease(
        begin,
        CredentialVersionRef::new(provider, version).unwrap(),
    );
    measurements
        .issue_credential_verification_capability(
            lease,
            CredentialBindingDigest::from_measured(binding_digest).unwrap(),
        )
        .unwrap()
}

fn transport(response: QuotaRefreshResponse) -> Arc<FakeTransport> {
    Arc::new(FakeTransport {
        calls: AtomicUsize::new(0),
        endpoint: Mutex::new(None),
        auth: Mutex::new(None),
        responses: Mutex::new(VecDeque::from([response])),
    })
}

fn response(body: &[u8]) -> QuotaRefreshResponse {
    QuotaRefreshResponse {
        status: 200,
        content_type: Some("application/json; charset=utf-8".to_owned()),
        body: body.to_vec(),
    }
}

#[tokio::test]
async fn authorized_refresh_materializes_after_identity_and_expiry_checks() {
    let materializer = Arc::new(FakeMaterializer {
        calls: AtomicUsize::new(0),
        denied: false,
    });
    let transport = transport(response(
        br#"{"usage":{"used":"40","limit":"1000","resetTime":"2026-09-15T00:00:00Z"}}"#,
    ));
    let sink = Arc::new(QuotaStateStore::new());
    let refresher =
        AuthorizedQuotaRefresher::new(materializer.clone(), transport.clone(), sink.clone());
    let descriptor = QuotaRequestDescriptor::kimi_coding();
    let capability = capability(
        "kimi-coding",
        7,
        i64::MAX,
        descriptor.binding_digest(7, None),
    );
    let snapshot = refresher
        .refresh(&capability, &descriptor, None, 10)
        .await
        .unwrap();
    assert_eq!(snapshot.availability(), QuotaAvailability::Known);
    assert_eq!(materializer.calls.load(Ordering::Relaxed), 1);
    assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        *transport.auth.lock().unwrap(),
        Some(QuotaAuthHeaderKind::BearerAuthorization)
    );
    let identity = QuotaIdentity::new("kimi-coding", 7).unwrap();
    assert_eq!(sink.admission(&identity, 10).unwrap(), QuotaDecision::Allow);
}

#[tokio::test]
async fn refresh_rejects_wrong_provider_expiry_and_non_json_without_secret_access() {
    let materializer = Arc::new(FakeMaterializer {
        calls: AtomicUsize::new(0),
        denied: false,
    });
    let transport = transport(QuotaRefreshResponse {
        status: 200,
        content_type: Some("text/plain".to_owned()),
        body: b"{}".to_vec(),
    });
    let sink = Arc::new(QuotaStateStore::new());
    let refresher = AuthorizedQuotaRefresher::new(materializer.clone(), transport.clone(), sink);
    assert_eq!(
        refresher
            .refresh(
                &capability("openai", 1, i64::MAX, [3; 32]),
                &QuotaRequestDescriptor::kimi_coding(),
                None,
                10
            )
            .await,
        Err(QuotaRefreshStatus::Unauthorized)
    );
    assert_eq!(
        refresher
            .refresh(
                &capability(
                    "kimi-coding",
                    2,
                    2,
                    QuotaRequestDescriptor::kimi_coding().binding_digest(2, None),
                ),
                &QuotaRequestDescriptor::kimi_coding(),
                None,
                10
            )
            .await,
        Err(QuotaRefreshStatus::Unauthorized)
    );
    assert_eq!(
        refresher
            .refresh(
                &capability("kimi-coding", 3, i64::MAX, [3; 32],),
                &QuotaRequestDescriptor::kimi_coding(),
                None,
                10
            )
            .await,
        Err(QuotaRefreshStatus::Unauthorized)
    );
    assert_eq!(
        refresher
            .refresh(
                &capability(
                    "kimi-coding",
                    4,
                    i64::MAX,
                    QuotaRequestDescriptor::kimi_coding().binding_digest(4, None),
                ),
                &QuotaRequestDescriptor::kimi_coding(),
                None,
                10
            )
            .await,
        Err(QuotaRefreshStatus::UnknownSchema)
    );
    assert_eq!(materializer.calls.load(Ordering::Relaxed), 1);
    assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn unknown_refresh_failure_preserves_known_exhaustion_and_reset() {
    let materializer = Arc::new(FakeMaterializer {
        calls: AtomicUsize::new(0),
        denied: false,
    });
    let transport = Arc::new(FakeTransport {
        calls: AtomicUsize::new(0),
        endpoint: Mutex::new(None),
        auth: Mutex::new(None),
        responses: Mutex::new(VecDeque::from([
            response(
                br#"{"usage":{"used":"1000","limit":"1000","resetTime":"2026-09-15T00:00:00Z"}}"#,
            ),
            response(b"{}"),
        ])),
    });
    let sink = Arc::new(QuotaStateStore::new());
    let refresher = AuthorizedQuotaRefresher::new(materializer, transport, sink.clone());
    let descriptor = QuotaRequestDescriptor::kimi_coding();
    let first = capability(
        "kimi-coding",
        8,
        i64::MAX,
        descriptor.binding_digest(8, None),
    );
    refresher
        .refresh(&first, &descriptor, None, 10)
        .await
        .unwrap();
    assert!(matches!(
        sink.admission(&QuotaIdentity::new("kimi-coding", 8).unwrap(), 10),
        Ok(QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: Some(_)
        })
    ));
    assert_eq!(
        refresher.refresh(&first, &descriptor, None, 11).await,
        Err(QuotaRefreshStatus::UnknownSchema)
    );
    assert!(matches!(
        sink.admission(&QuotaIdentity::new("kimi-coding", 8).unwrap(), 11),
        Ok(QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: Some(_)
        })
    ));
}
