use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{
    BeginProviderCredentialEnrollment, LaunchSecret, ProtectedCredentialEnrollmentAdmissionBinding,
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
    ProtectedCredentialEnrollmentRequestBinding, ProviderCredentialBeginIntentBinding,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialReadinessRevision,
    ProviderCredentialEnrollmentStore, ProviderId,
};

use super::super::coordinator::ProviderCredentialBeginAdmission;
use super::super::verified_frames::ProviderCredentialVerifiedFrameGate;

pub(crate) struct Session {
    pub(crate) request_frame: Vec<u8>,
    pub(crate) admission_frame: Vec<u8>,
    pub(crate) request_binding: ProtectedCredentialEnrollmentRequestBinding,
    pub(crate) admission_binding: ProtectedCredentialEnrollmentAdmissionBinding,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
}

pub(crate) fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

pub(crate) fn command() -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "idempotency-a",
        "intent-a",
    )
    .unwrap()
}

pub(crate) fn session(key: [u8; 32]) -> Session {
    session_with(key, &command(), &super::begin_admission_support::context())
}

pub(crate) fn session_with(
    key: [u8; 32],
    command: &BeginProviderCredentialEnrollment,
    context: &ProviderCredentialCommandContext,
) -> Session {
    let keys = LaunchSecret::from_bytes(key).unwrap().derive_keys();
    let authenticator =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let intent = ProviderCredentialBeginIntentBinding::new(command, context);
    let issued_at = now_millis();
    let expires_at = issued_at + 20_000;
    let request_binding = ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        3,
        2,
        uuid(4),
        [4; 32],
        [5; 32],
        [6; 32],
        [7; 32],
        runne_api::protected_credential_native_intent_digest(command.native_intent_id()),
        *intent.action_provider_revision_digest(),
        *intent.command_identity_digest(),
        issued_at,
        expires_at,
    )
    .unwrap();
    let request = authenticator
        .issue_request(request_binding.clone(), 1)
        .unwrap();
    let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(request).encode_frame();
    let verified = authenticator
        .decode_request(&request_frame, &request_binding, 0, issued_at + 1_000)
        .unwrap();
    let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        [8; 32],
        [4; 32],
        [9; 32],
        2,
        [10; 32],
        4,
        [5; 32],
        [6; 32],
        [7; 32],
        uuid(5),
        expires_at,
    )
    .unwrap();
    let admission = authenticator
        .issue_admission(&verified, admission_binding.clone(), 2)
        .unwrap();
    let admission_frame =
        ProtectedCredentialEnrollmentControlFrame::Admission(admission).encode_frame();
    Session {
        request_frame,
        admission_frame,
        request_binding,
        admission_binding,
        issued_at,
        expires_at,
    }
}

pub(crate) fn snapshot() -> CredentialLifecycleSnapshot {
    CredentialLifecycleSnapshot::new(
        ProviderId::new("openai").unwrap(),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        1,
    )
    .unwrap()
}

pub(crate) struct Fixture {
    pub(crate) gate: ProviderCredentialVerifiedFrameGate,
    pub(crate) store: runne_store::provider::SqliteProviderCredentialLifecycleStore,
    _directory: tempfile::TempDir,
}

pub(crate) fn fixture(key: [u8; 32]) -> Fixture {
    let keys = LaunchSecret::from_bytes(key).unwrap().derive_keys();
    let authenticator =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("frames.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    Fixture {
        gate: ProviderCredentialVerifiedFrameGate::new(
            authenticator,
            ProviderCredentialRequestAuthorityPair::new(),
            measurements,
        ),
        store,
        _directory: directory,
    }
}

impl ProviderCredentialVerifiedFrameGate {
    pub(crate) fn admit<'a, S: ProviderCredentialEnrollmentStore>(
        &'a self,
        session: &'a Session,
        command: &'a BeginProviderCredentialEnrollment,
        context: &'a ProviderCredentialCommandContext,
        snapshot: CredentialLifecycleSnapshot,
        store: &'a S,
    ) -> Result<ProviderCredentialBeginAdmission, ProviderCredentialEnrollmentHostError> {
        self.admit_at(
            session,
            session.issued_at + 1_000,
            command,
            context,
            snapshot,
            store,
        )
    }

    pub(crate) fn admit_at<'a, S: ProviderCredentialEnrollmentStore>(
        &'a self,
        session: &'a Session,
        now_unix_millis: u64,
        command: &'a BeginProviderCredentialEnrollment,
        context: &'a ProviderCredentialCommandContext,
        snapshot: CredentialLifecycleSnapshot,
        store: &'a S,
    ) -> Result<ProviderCredentialBeginAdmission, ProviderCredentialEnrollmentHostError> {
        self.admit_verified_begin(
            &session.request_frame,
            &session.admission_frame,
            &session.request_binding,
            &session.admission_binding,
            0,
            1,
            now_unix_millis,
            command,
            context,
            snapshot,
            store,
        )
    }
}
