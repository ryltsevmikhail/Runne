use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use runne_api::{
    ApiPrincipalId, BeginProviderCredentialEnrollment, DaemonInstanceId, EventLogLineageId,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2, RuntimeSessionBinding,
    StableRuntimeBinding,
};
use runne_application::local_session::LocalSessionService;
use runne_domain::event::Sensitivity;
use runne_native_qualification::QualificationAdmissionVerifier;
use runne_provider::{CredentialAuthorityPair, CredentialEnrollmentAuthorityPair};
use runne_secure_store::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialReadback, SecureStoreError,
};

use super::super::{V3EnrollmentDispatch, run_control_loop_v3_entered};
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
use crate::protected_activation::{
    ProtectedActivationChannel, enrollment_control_transition::DaemonEnrollmentRendezvous,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

struct BoundedThread<T> {
    result: mpsc::Receiver<T>,
    handle: JoinHandle<()>,
}

impl<T: Send + 'static> BoundedThread<T> {
    fn spawn(action: impl FnOnce() -> T + Send + 'static) -> Self {
        let (sender, result) = mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || sender.send(action()).unwrap());
        Self { result, handle }
    }

    fn wait(self, phase: &str) -> T {
        let result = self
            .result
            .recv_timeout(TEST_TIMEOUT)
            .unwrap_or_else(|error| panic!("{phase} exceeded {TEST_TIMEOUT:?}: {error}"));
        self.handle.join().unwrap();
        result
    }
}

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

#[test]
fn connected_supervisor_relay_closes_before_request_and_cannot_cross_session() {
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let verified = Arc::new(AtomicUsize::new(0));
    let fixture = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let (mut supervisor, desktop_peer, keys, owned, installed) = fixture.into_parts();
    let first_session = *owned.session_id();
    let (control, database) = control();
    let (mut proxy_daemon, daemon_channel) = UnixStream::pair().unwrap();
    let daemon = spawn_daemon(
        daemon_channel,
        keys,
        owned.clone(),
        installed,
        Arc::clone(&control),
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        ),
        Arc::clone(&verified),
    );
    let proxy = BoundedThread::spawn(move || {
        let mut desktop_peer = desktop_peer;
        let context =
            crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        let fault = crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        assert_eq!(&context[4..12], b"RNQCTX1\0");
        assert_eq!(&fault[4..12], b"RNQFRLY1");
        let relay = [context, fault].concat();
        proxy_daemon.write_all(&relay).unwrap();
        desktop_peer
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!(
            matches!(desktop_peer.read(&mut [0; 1]), Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
        );
        assert_eq!(proxy_daemon.read(&mut [0; 1]).unwrap(), 0);
        relay
    });
    let begin =
        runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin::new(command(), [9; 32])
            .unwrap();
    let started = Instant::now();
    assert!(
        supervisor
            .begin_protected_credential_enrollment_with_qualification(
                begin,
                Some(super::qualification_admission_tests::support::admission(
                    &context_key,
                    &fault_key,
                )),
            )
            .is_err()
    );
    assert!(started.elapsed() < TEST_TIMEOUT);
    let relay = proxy.wait("relay proxy/daemon close");
    assert!(daemon.wait("first daemon close").is_err());
    assert_eq!(
        verified.load(Ordering::SeqCst),
        2,
        "registration must complete before combined verification"
    );
    assert_zero_operations(database.path().join("relay-control.sqlite3"));
    let cleanup = BoundedThread::spawn(move || {
        let stopped = supervisor.stop();
        (stopped, supervisor.owns_runtime())
    });
    let (stopped, owns_runtime) = cleanup.wait("first supervisor cleanup");
    assert_eq!(
        stopped.unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
    assert!(!owns_runtime);

    let next = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let (mut next_supervisor, unused_peer, next_keys, next_owned, next_installed) =
        next.into_parts();
    assert_ne!(next_owned.session_id(), &first_session);
    let (mut old_sender, next_daemon_channel) = UnixStream::pair().unwrap();
    let next_daemon = spawn_daemon(
        next_daemon_channel,
        next_keys,
        next_owned,
        next_installed,
        control,
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        ),
        Arc::clone(&verified),
    );
    old_sender.write_all(&relay).unwrap();
    drop(old_sender);
    assert!(next_daemon.wait("second daemon close").is_err());
    assert_eq!(
        verified.load(Ordering::SeqCst),
        2,
        "cross-session relay verified"
    );
    assert_zero_operations(database.path().join("relay-control.sqlite3"));
    drop(unused_peer);
    let cleanup = BoundedThread::spawn(move || next_supervisor.stop());
    assert_eq!(
        cleanup.wait("second supervisor cleanup").unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
}

fn spawn_daemon(
    channel: UnixStream,
    keys: runne_api::ProtectedActivationKeys,
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    verifier: QualificationAdmissionVerifier,
    verified: Arc<AtomicUsize>,
) -> BoundedThread<Result<(), runne_api::LaunchAuthorityError>> {
    let sessions = sessions_for(&owned);
    let channel = ProtectedActivationChannel::new(channel).unwrap();
    BoundedThread::spawn(move || {
        run_control_loop_v3_entered(
            channel,
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::from_secs(1)),
            Arc::new(|| Ok(1_800_000_000_000)),
            V3EnrollmentDispatch::new(
                Some(control),
                DaemonEnrollmentRendezvous::for_test(),
                Some(installed),
            )
            .with_test_qualification(verifier, verified),
        )
    })
}

fn sessions_for(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Arc<Mutex<LocalSessionService>> {
    let stable = owned.stable();
    let stable = StableRuntimeBinding::new(
        *stable.authority_id(),
        ApiPrincipalId::new(stable.principal_id()).unwrap(),
        EventLogLineageId::from_bytes(*stable.lineage_id()),
        stable.profile_id(),
        *stable.profile_hash(),
        *stable.capability_digest(),
    )
    .unwrap();
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes(*owned.daemon_instance_id()),
        owned.launch_generation(),
        *owned.session_id(),
        0,
        Sensitivity::Public,
        [14; 32],
    )
    .unwrap();
    Arc::new(Mutex::new(
        LocalSessionService::new_protected(
            binding,
            [16; 32],
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap(),
    ))
}

fn control() -> (
    Arc<DaemonProviderCredentialEnrollmentControl>,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("relay-control.sqlite3");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment_store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &database,
            lifecycle,
            enrollment_store.clone(),
        )
        .unwrap();
    let control = DaemonProviderCredentialEnrollmentControl::new(
        Arc::new(store),
        Arc::new(NoReadback),
        measurements,
        enrollment_store,
        [9; 16],
        10,
        None,
    )
    .unwrap();
    (Arc::new(control), directory)
}

fn command() -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "qualification-relay",
        "native-intent",
    )
    .unwrap()
}

fn assert_zero_operations(database: impl AsRef<std::path::Path>) {
    let connection = rusqlite::Connection::open(database).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "relay reached Begin/effect persistence");
}
