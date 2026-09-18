use super::*;
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
use runne_api::{
    ApiActor, ApiPrincipalId, ProviderCredentialOperationStateV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialVerifyIntentBinding,
};
use runne_daemon_chat_completions_effect::{
    QuotaRefreshResponse, QuotaRefreshTransport, QuotaRefreshTransportError,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialVerification,
    BindCredentialReadback, ClaimCredentialOperation, CompleteCredentialVerification,
    CredentialAuthorityPair, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialOperationAction, CredentialOperationId, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialVerificationCapability, CredentialVerificationKind,
    CredentialVerificationObservation, CredentialVerificationResult, CredentialVerifierRevision,
    CredentialVersionRef, IssueCredentialTicketDigest, ObserveNativeEffect,
    ProviderCredentialEnrollmentStore, ProviderId,
};
use runne_provider_quota::{QuotaDecision, QuotaIdentity, QuotaStateStore};
use runne_secure_store::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, ProviderCredentialReadback,
    ProviderCredentialVerificationMaterializer, SecureStoreError, VerificationMaterializerAdapter,
    VerificationNativeMaterializer,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;
include!("remote_tests_support.rs");

struct NoReadback;

impl ProviderCredentialReadback for NoReadback {
    fn readback_exact_version(
        &self,
        _: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
    fn readback_exact_absence(
        &self,
        _: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
}

struct NativeRead {
    calls: Arc<AtomicUsize>,
}

impl VerificationNativeMaterializer for NativeRead {
    fn materialize_for_verification(
        &self,
        capability: &CredentialVerificationCapability,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(capability.lease().provider().as_str(), "kimi-coding");
        assert_eq!(capability.lease().active_credential_version().version(), 1);
        ProviderCredentialMaterial::new(b"quota-fixture".to_vec())
    }
}

struct FakeTransport {
    calls: AtomicUsize,
    responses: Mutex<VecDeque<Vec<u8>>>,
}

impl QuotaRefreshTransport for FakeTransport {
    fn get<'a>(
        &'a self,
        _: String,
        _: runne_provider_quota::QuotaAuthHeaderKind,
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
        assert_eq!(&*token, b"quota-fixture");
        let body = self.responses.lock().unwrap().pop_front().unwrap();
        Box::pin(async move {
            Ok(QuotaRefreshResponse {
                status: 200,
                content_type: Some("application/json".into()),
                body,
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_remote_verify_reads_exact_version_records_quota_and_preserves_exhaustion() {
    let (store, measurements, release, store_authority) = ready_store();
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("runne");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let access = ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap();
    let native_calls = Arc::new(AtomicUsize::new(0));
    let materializer: Arc<dyn ProviderCredentialVerificationMaterializer> =
        Arc::new(VerificationMaterializerAdapter::new(
            NativeRead {
                calls: Arc::clone(&native_calls),
            },
            access,
        ));
    let transport = Arc::new(FakeTransport {
        calls: AtomicUsize::new(0),
        responses: Mutex::new(VecDeque::from([
            br#"{"usage":{"used":"1000","limit":"1000","resetTime":"2026-09-15T00:00:00Z"}}"#
                .to_vec(),
            br#"{}"#.to_vec(),
        ])),
    });
    let quota = Arc::new(QuotaStateStore::new());
    let control = Arc::new(
        DaemonProviderCredentialEnrollmentControl::new(
            Arc::clone(&store),
            Arc::new(NoReadback),
            measurements.clone(),
            store_authority,
            [9; 16],
            1,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
        .unwrap(),
    );
    let verifier = RemoteProviderCredentialVerification::new(
        Arc::clone(&store),
        measurements,
        control.operation_handle_issuer(),
        materializer,
        Arc::clone(&transport),
        quota.clone(),
        ProviderCredentialProviderV2::KimiCoding,
        None,
        None,
    );
    control.install_verification(Arc::new(verifier)).unwrap();
    let current = ProviderCredentialEnrollmentStore::current_verification_context(
        &*store,
        &ProviderId::new("kimi-coding").unwrap(),
    )
    .unwrap();
    assert_eq!(current.lifecycle_revision().get(), 2);
    assert_eq!(current.release_tuple_digest(), release);

    let first = verify_once(Arc::clone(&control), release, 1).await.unwrap();
    assert_eq!(first.state(), ProviderCredentialOperationStateV2::Completed);
    assert_eq!(
        first.last_disposition(),
        Some(ProviderCredentialLastDispositionV2::Completed)
    );
    let status = ProviderCredentialEnrollmentStore::safe_snapshot(
        &*store,
        &ProviderId::new("kimi-coding").unwrap(),
    )
    .unwrap();
    assert_eq!(
        status.verification().kind(),
        Some(CredentialVerificationKind::Remote)
    );
    assert_eq!(
        status.verification().result(),
        Some(CredentialVerificationResult::Verified)
    );
    assert!(matches!(
        quota.admission(&QuotaIdentity::new("kimi-coding", 1).unwrap(), 10),
        Ok(QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: Some(_)
        })
    ));

    let second = verify_once(Arc::clone(&control), release, 2).await.unwrap();
    assert_eq!(
        second.last_disposition(),
        Some(ProviderCredentialLastDispositionV2::Unsupported)
    );
    assert_eq!(native_calls.load(Ordering::Relaxed), 2);
    assert_eq!(transport.calls.load(Ordering::Relaxed), 2);
    assert!(matches!(
        quota.admission(&QuotaIdentity::new("kimi-coding", 1).unwrap(), 10),
        Ok(QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: Some(_)
        })
    ));
}
