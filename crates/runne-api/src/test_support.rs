use crate::ReplayPromotionProjectionV1;
pub use crate::protected_activation::test_support::{admission, claims, into_untrusted_admission};
use runne_domain::conversation::{Conversation, ConversationEvent};
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, MessageId,
    TaskRunId, WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::timestamp::Timestamp;

/// Exact opt-in for the local, unqualified native-enrollment process fixture.
#[must_use]
pub fn local_native_enrollment_enabled() -> bool {
    validated_local_native_enrollment_case_name().is_some()
}

fn local_native_enrollment_opted_in() -> bool {
    std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        == Some(std::ffi::OsStr::new("1"))
}

/// Closed fault/audit cases admitted only inside the package-shaped local fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalNativeEnrollmentCase {
    ReleaseWrong,
    ReleaseReplayed,
    ReleaseMissing,
    DeathReleased,
    DeathReadback,
    Leakage,
}

impl LocalNativeEnrollmentCase {
    /// Returns the exact opaque fixture selector propagated to real children.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseWrong => "release-wrong",
            Self::ReleaseReplayed => "release-replayed",
            Self::ReleaseMissing => "release-missing",
            Self::DeathReleased => "death-released",
            Self::DeathReadback => "death-readback",
            Self::Leakage => "leakage",
        }
    }
}

/// Resolves a closed local process case only after validating the owned package root.
#[must_use]
pub fn local_native_enrollment_case() -> Option<LocalNativeEnrollmentCase> {
    let name = validated_local_native_enrollment_case_name()?;
    match name.as_str() {
        "release-wrong" => Some(LocalNativeEnrollmentCase::ReleaseWrong),
        "release-replayed" => Some(LocalNativeEnrollmentCase::ReleaseReplayed),
        "release-missing" => Some(LocalNativeEnrollmentCase::ReleaseMissing),
        "death-released" => Some(LocalNativeEnrollmentCase::DeathReleased),
        "death-readback" => Some(LocalNativeEnrollmentCase::DeathReadback),
        "leakage" => Some(LocalNativeEnrollmentCase::Leakage),
        _ => None,
    }
}

/// Returns the validated fixture root and exact known scenario for child launch.
#[must_use]
pub fn validated_local_native_enrollment_case_name() -> Option<String> {
    if !local_native_enrollment_opted_in() {
        return None;
    }
    let root = std::fs::canonicalize(std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT")?).ok()?;
    let home = std::fs::canonicalize(std::env::var_os("HOME")?).ok()?;
    let keychain = std::fs::canonicalize(std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN")?).ok()?;
    let executable = std::fs::canonicalize(std::env::current_exe().ok()?).ok()?;
    let macos = root.join("Runne.app/Contents/MacOS");
    if !root.is_absolute()
        || home != root.join("home")
        || keychain != home.join("Library/Keychains/runne-ci.keychain-db")
        || executable.parent() != Some(macos.as_path())
        || !matches!(
            executable.file_name()?.to_str()?,
            "runne-desktop" | "runne" | "runned"
        )
    {
        return None;
    }
    let scenario = std::env::var("RUNNE_SLICE_E_SCENARIO").ok()?;
    matches!(
        scenario.as_str(),
        "release-wrong"
            | "release-replayed"
            | "release-missing"
            | "death-released"
            | "death-readback"
            | "leakage"
            | "death-prepared"
            | "death-claimed"
            | "joined"
            | "wrong"
            | "replaced"
            | "stale"
            | "acl"
    )
    .then_some(scenario)
}

/// Creates a complete Conversation promotion fixture for native host tests.
#[must_use]
pub fn conversation_promotion_bytes(conversation_id: [u8; 16], workspace_id: [u8; 16]) -> Vec<u8> {
    let id = ConversationId::from_bytes(conversation_id);
    let command = Conversation::decide_create(id, WorkspaceId::from_bytes(workspace_id));
    let aggregate = command.aggregate_id().clone();
    let created = envelope(
        bytes(1),
        aggregate.clone(),
        None,
        command.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        Sensitivity::Public,
    );
    let committed = Timestamp::from_unix_micros(1_722_330_000_000_002);
    let appended = envelope(
        bytes(3),
        aggregate,
        Some(*created.event_id()),
        ConversationEvent::UserMessageAppended {
            message_id: MessageId::from_bytes(bytes(4)),
            taskrun_id: TaskRunId::from_bytes(bytes(5)),
            attempt_id: AttemptId::from_bytes(bytes(6)),
            text: MessageText::new("promoted historical text").expect("fixture"),
        },
        2,
        committed,
        Sensitivity::Sensitive,
    );
    ReplayPromotionProjectionV1::encode_conversation(
        &Conversation::replay(&[created, appended])
            .expect("fixture")
            .snapshot_v1(),
        &[committed],
    )
    .expect("fixture")
}

fn envelope<T: Clone>(
    event: [u8; 16],
    aggregate: runne_domain::id::AggregateId,
    previous: Option<EventId>,
    payload: T,
    sequence: u64,
    timestamp: Timestamp,
    sensitivity: Sensitivity,
) -> EventEnvelope<T> {
    EventEnvelope::from_parts(
        EventId::from_bytes(event),
        aggregate.clone(),
        aggregate,
        previous,
        CommandId::from_bytes(bytes(9)),
        IdempotencyKey::new(format!("api-fixture-{sequence}")).expect("fixture"),
        1,
        Actor::new("test").expect("fixture"),
        sensitivity,
        payload,
        sequence,
        timestamp,
        IntegrityDigest::from_bytes([sequence as u8; 32]),
    )
}

const fn bytes(last: u8) -> [u8; 16] {
    [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, last]
}
