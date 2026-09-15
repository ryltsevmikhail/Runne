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

fn verify_once(
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    release: CredentialBindingDigest,
    suffix: u8,
) -> impl std::future::Future<
    Output = Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError>,
> {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let command = VerifyProviderCredential::new(
        ProviderCredentialProviderV2::KimiCoding,
        2,
        ProviderCredentialVerificationKindV2::Remote,
        format!("00000000-0000-7000-8000-00000000000{suffix}"),
        format!("native-{suffix}"),
    )
    .unwrap();
    let context = ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity()).unwrap(),
        idempotency_key: IdempotencyKey::new(command.command_identity()).unwrap(),
        principal: ApiPrincipalId::new("protected-desktop-owner").unwrap(),
        actor: ApiActor::new("runne-tauri-native-host").unwrap(),
    };
    let binding = ProviderCredentialVerifyIntentBinding::new(&command, &context);
    let authority = issuer
        .issue_base([1; 32], release.as_bytes(), [3; 32], 8, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof(
            [5 + suffix; 32],
            *authority.protected_session_id(),
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    async move {
        tokio::task::spawn_blocking(move || {
            control.verify_admitted(verifier, authority, proof, context, command)
        })
        .await
        .unwrap()
    }
}

fn ready_store() -> (
    Arc<runne_store::provider::SqliteProviderCredentialLifecycleStore>,
    CredentialEnrollmentMeasurementAuthority,
    CredentialBindingDigest,
    CredentialEnrollmentStoreAuthority,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("remote-verification.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (store_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &path,
            lifecycle,
            store_authority.clone(),
        )
        .unwrap(),
    );
    let provider = ProviderId::new("kimi-coding").unwrap();
    let head =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(&*store, &provider).unwrap();
    let active =
        CredentialVersionRef::new(provider.clone(), head.next_credential_version()).unwrap();
    let release_tuple = measurements
        .issue_qualified_credential_release_tuple(
            measurements.release_manifest_digest([0x40; 32]).unwrap(),
        )
        .unwrap();
    let release = release_tuple.digest();
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([2; 16]),
        IdempotencyKey::new("seed-remote").unwrap(),
        operation,
        CredentialInstallationOwnerId::from_bytes([0x30; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(active.clone()),
        None,
        head.lifecycle_revision(),
        head.fence(),
        digest(0x41),
        4_000_000_000,
    )
    .unwrap()
    .with_qualified_release_tuple(release_tuple);
    ProviderCredentialEnrollmentStore::begin(&*store, begin).unwrap();
    let continuation = digest(0x42);
    ProviderCredentialEnrollmentStore::attach_process(
        &*store,
        AttachCredentialProcess::new(operation, continuation).unwrap(),
    )
    .unwrap();
    let ticket_digest = digest(0x43);
    let ticket = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &*store,
        IssueCredentialTicketDigest::new(operation, ticket_digest, continuation, 300).unwrap(),
    )
    .unwrap();
    let draft =
        ClaimCredentialOperation::new(ticket, ticket_digest, continuation, digest(0x44), 1, 1)
            .unwrap();
    let measured = measurement_snapshot(&measurements, &draft);
    let claim_binding = measurements
        .measure_claim_operation(&measured, &draft)
        .unwrap();
    let bound = draft.bind_process_release_digest(claim_binding).unwrap();
    ProviderCredentialEnrollmentStore::claim(
        &*store,
        measurements.seal_claim_operation(measured, bound).unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &*store,
        ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(
        &*store,
        BindCredentialReadback::new(
            operation,
            CredentialReadbackDisposition::ExactVersion,
            digest(0x45),
        )
        .unwrap(),
    )
    .unwrap();
    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes([3; 16]).unwrap(),
        Some(operation),
        provider,
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap()),
        release,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete(
        &*store,
        runne_provider::CompleteCredentialOperation::new(
            operation,
            BindCredentialReadback::new(
                operation,
                CredentialReadbackDisposition::ExactVersion,
                digest(0x45),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            runne_provider::CredentialFence::new(1).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();
    seed_local_verification(&store);
    (store, measurements, release, store_authority)
}

fn seed_local_verification(store: &SqliteProviderCredentialLifecycleStore) {
    let provider = ProviderId::new("kimi-coding").unwrap();
    let current =
        ProviderCredentialEnrollmentStore::current_verification_context(store, &provider).unwrap();
    let observation = CredentialOperationId::from_bytes([4; 16]).unwrap();
    let lease = ProviderCredentialEnrollmentStore::begin_verification(
        store,
        BeginCredentialVerification::new(
            observation,
            None,
            provider,
            CredentialVerificationKind::Local,
            current.lifecycle_revision(),
            current.fence(),
            current.readiness_revision(),
            current.release_tuple_digest(),
            digest(0x46),
            CredentialVerifierRevision::new(1).unwrap(),
            current.observed_at_high_water(),
            4_000_000_000,
        )
        .unwrap(),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete_verification(
        store,
        CompleteCredentialVerification::new(
            CredentialVerificationObservation::new(
                lease.observation_id(),
                CredentialVerificationResult::Verified,
                current.observed_at_high_water(),
            )
            .unwrap(),
            current.lifecycle_revision(),
            current.fence(),
        ),
    )
    .unwrap();
}

fn measurement_snapshot(
    authority: &CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> runne_provider::CredentialMeasurementSnapshot {
    runne_provider::CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([0x50; 32]).unwrap(),
        authority.release_manifest_digest([0x51; 32]).unwrap(),
        authority.desktop_executable_identity([0x52; 32]).unwrap(),
        authority.writer_executable_identity([0x53; 32]).unwrap(),
        authority.reader_executable_identity([0x54; 32]).unwrap(),
        authority.contract_bundle_digest([0x55; 32]).unwrap(),
        authority.daemon_authority_id([0x56; 32]).unwrap(),
        authority.protected_session_id([0x57; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(claim.desktop_supervisor_generation())
            .unwrap(),
        authority.writer_launch_id([0x58; 32]).unwrap(),
        authority.writer_process_start_identity([0x59; 32]).unwrap(),
        authority
            .writer_process_handle_identity([0x5a; 32])
            .unwrap(),
        authority.broker_channel_binding([0x5b; 32]).unwrap(),
        authority
            .continuation_binding_digest(claim.continuation_binding_digest().as_bytes())
            .unwrap(),
    )
    .unwrap()
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
