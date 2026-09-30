//! X2 writer lease two-client acceptance (plan 18 §D1.3/X2): the first
//! mutating principal acquires the durable conversation writer lease; a
//! second principal is fenced until an authenticated take-control with the
//! exact fencing token rotates ownership; the previous writer is then fenced.

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, ConversationContextScope,
    CreateConversationRequest, CreateProjectRequest, CreateWorkspaceRequest, GenerateTextRequest,
    LocalRuntimeProfile,
};

struct Daemon {
    _directory: tempfile::TempDir,
    profile: std::path::PathBuf,
    _stop: tokio::sync::oneshot::Sender<()>,
    _task: tokio::task::JoinHandle<()>,
}

async fn start() -> Daemon {
    let directory = tempfile::tempdir().expect("temp directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure temp directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    "127.0.0.1:0".clone_into(&mut defaults.http_bind);
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = Box::pin(DaemonApplication::start(&config))
        .await
        .expect("start daemon");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        application
            .run(async {
                let _ = stopped.await;
                Ok::<(), runne_daemon::error::DaemonError>(())
            })
            .await
            .expect("daemon run");
    });
    let profile = std::path::PathBuf::from(&config.replay_integrity_key_path)
        .with_file_name("client-profile.json");
    Daemon {
        _directory: directory,
        profile,
        _stop: stop,
        _task: task,
    }
}

/// Connects a SECOND session on the same profile: a distinct authenticated
/// principal sharing one daemon.
async fn second_client(profile: &std::path::Path) -> AuthenticatedRuntimeClient {
    LocalRuntimeProfile::load(profile)
        .expect("load profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("second session")
}

fn identity(label: &'static str) -> CommandIdentity {
    let id = CanonicalId::now_v7();
    CommandIdentity::new(id, label).expect("identity")
}

async fn seed(client: &AuthenticatedRuntimeClient) -> CanonicalId {
    let project = CanonicalId::now_v7();
    let workspace = CanonicalId::now_v7();
    let conversation = CanonicalId::now_v7();
    client
        .create_project(
            CreateProjectRequest::new(identity("lease-project"), project, "lease-e2e").expect("p"),
        )
        .await
        .expect("project");
    client
        .create_workspace(
            CreateWorkspaceRequest::new(
                identity("lease-workspace"),
                project,
                workspace,
                "lease-e2e",
            )
            .expect("w"),
        )
        .await
        .expect("workspace");
    client
        .create_conversation(CreateConversationRequest::new(
            identity("lease-conversation"),
            conversation,
            workspace,
            ConversationContextScope::Workspace,
        ))
        .await
        .expect("conversation");
    conversation
}

async fn try_generate(
    client: &AuthenticatedRuntimeClient,
    conversation: CanonicalId,
    version: u64,
) -> Result<(), runne_runtime_client::RuntimeApiError> {
    client
        .generate_text(
            GenerateTextRequest::new(
                identity("lease-generate"),
                conversation,
                version,
                "writer lease e2e",
            )
            .expect("g"),
        )
        .await
        .map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_lease_two_client_fencing_and_take_control() {
    let daemon = start().await;
    let alice = LocalRuntimeProfile::load(&daemon.profile)
        .expect("profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("alice session");
    let conversation = seed(&alice).await;

    // Alice's first mutation acquires the lease and completes generation.
    try_generate(&alice, conversation, 1)
        .await
        .expect("alice acquires and generates");

    // Bob (a second principal) is fenced on the same conversation.
    let bob = second_client(&daemon.profile).await;
    let fenced = try_generate(&bob, conversation, 3)
        .await
        .expect_err("bob fenced");
    assert_eq!(
        fenced.kind(),
        runne_runtime_client::RuntimeApiErrorKind::Conflict,
        "writer fencing is a typed 409 conflict, got {fenced:?}"
    );

    // Bob takes control with the exact expected fencing token (1 from
    // Alice's acquisition): the lease rotates.
    let ack = bob
        .take_control_conversation_writer_lease(conversation, 1)
        .await
        .expect("take control");
    assert_eq!(ack.fencing_token(), 2, "token rotates to 2");

    // Alice (the fenced prior writer) is now denied.
    let refenced = try_generate(&alice, conversation, 3)
        .await
        .expect_err("alice fenced after losing the lease");
    assert_eq!(
        refenced.kind(),
        runne_runtime_client::RuntimeApiErrorKind::Conflict
    );

    // A stale take-control token conflicts without rotation.
    let stale = alice
        .take_control_conversation_writer_lease(conversation, 1)
        .await
        .expect_err("stale token conflicts");
    assert_eq!(
        stale.kind(),
        runne_runtime_client::RuntimeApiErrorKind::Conflict
    );

    // Bob's ownership is real: his generate on a FRESH conversation (the
    // single-turn contract rejects a second turn on the original) completes.
    let bob_conversation = seed(&bob).await;
    try_generate(&bob, bob_conversation, 1)
        .await
        .expect("bob generates on his own fresh conversation after take control");
}
