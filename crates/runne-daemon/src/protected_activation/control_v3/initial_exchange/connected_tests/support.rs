use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

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

use super::super::super::{V3EnrollmentDispatch, run_control_loop_v3_entered};
use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
use crate::protected_activation::{
    ProtectedActivationChannel, enrollment_control_transition::DaemonEnrollmentRendezvous,
};

pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct BoundedThread<T> {
    result: mpsc::Receiver<T>,
    handle: JoinHandle<()>,
}

impl<T: Send + 'static> BoundedThread<T> {
    pub(super) fn spawn(action: impl FnOnce() -> T + Send + 'static) -> Self {
        let (sender, result) = mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || sender.send(action()).unwrap());
        Self { result, handle }
    }

    pub(super) fn wait(self, phase: &str) -> T {
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

pub(super) fn spawn_daemon(
    channel: std::os::unix::net::UnixStream,
    keys: runne_api::ProtectedActivationKeys,
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    verifier: QualificationAdmissionVerifier,
    verified: Arc<std::sync::atomic::AtomicUsize>,
) -> BoundedThread<Result<(), runne_api::LaunchAuthorityError>> {
    spawn_daemon_with_rendezvous(
        channel,
        keys,
        owned,
        installed,
        control,
        verifier,
        verified,
        DaemonEnrollmentRendezvous::for_test(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_daemon_with_rendezvous(
    channel: std::os::unix::net::UnixStream,
    keys: runne_api::ProtectedActivationKeys,
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    verifier: QualificationAdmissionVerifier,
    verified: Arc<std::sync::atomic::AtomicUsize>,
    rendezvous: DaemonEnrollmentRendezvous,
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
            V3EnrollmentDispatch::new(Some(control), rendezvous, Some(installed))
                .with_test_qualification(verifier, Arc::new(|| Ok(1_800_000_000)), verified),
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

pub(super) fn control() -> (
    Arc<DaemonProviderCredentialEnrollmentControl>,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let database = {
        let daemon = directory.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("relay-control.sqlite3")
    };
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

pub(super) fn command() -> BeginProviderCredentialEnrollment {
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

/// Relay fixture databases live at
/// `<tempdir>/runne-daemon/relay-control.sqlite3` (nested for the identity
/// guard); plain readers must open the same nested path.
pub(super) fn relay_db(root: &std::path::Path) -> std::path::PathBuf {
    root.join("runne-daemon").join("relay-control.sqlite3")
}

pub(super) fn assert_zero_operations(database: impl AsRef<std::path::Path>) {
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
