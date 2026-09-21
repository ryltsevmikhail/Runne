//! Shared fixture and runner helpers for the live `task` CLI tests: a real
//! in-process daemon, the real CLI binary, and seeding strictly through the
//! public runtime client.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use runne_api::ConversationContextScope;
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, CreateConversationRequest,
    CreateProjectRequest, CreateWorkspaceRequest, LocalRuntimeProfile, SubmitTaskRunRequest,
    TaskRunSubmitAcknowledgement,
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct RunningDaemon {
    _directory: tempfile::TempDir,
    pub profile: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), DaemonError>>,
}

pub async fn start_test_daemon() -> RunningDaemon {
    let directory = tempfile::tempdir().expect("temp directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure temp directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    "127.0.0.1:0".clone_into(&mut defaults.http_bind);
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = Box::pin(DaemonApplication::start(&config))
        .await
        .expect("start daemon");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(async move {
        application
            .run(async move {
                stopped
                    .await
                    .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
            })
            .await
    });
    let profile =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    RunningDaemon {
        _directory: directory,
        profile,
        stop: Some(stop),
        task: daemon,
    }
}

/// Signals shutdown but keeps the fixture directory (and the profile) alive so
/// post-shutdown observations stay deterministic.
pub async fn stop_daemon(daemon: &mut RunningDaemon) {
    daemon
        .stop
        .take()
        .expect("stop sender still present")
        .send(())
        .expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), &mut daemon.task)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");
}

pub async fn run_cli(arguments: &[&str]) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_runne");
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    tokio::task::spawn_blocking(move || Command::new(executable).args(arguments).output())
        .await
        .expect("join CLI")
        .expect("run CLI")
}

pub fn exit_code(output: &std::process::Output) -> i32 {
    output.status.code().expect("CLI exits with a code")
}

pub fn stdout_string(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout")
}

pub fn parse_json_error_envelope(
    output: &std::process::Output,
    context: &str,
) -> serde_json::Value {
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    let envelope: serde_json::Value = serde_json::from_str(&stderr).expect("JSON error envelope");
    assert_eq!(envelope["schemaVersion"], 1, "{context}");
    assert_eq!(envelope["ok"], false, "{context}");
    envelope
}

/// JSON clients perform exactly one parse: `data` must be the typed payload,
/// never a pre-serialized JSON string such as `data.output = "{...}"`.
pub fn parse_typed_success_data(output: &std::process::Output, command: &str) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one-parse JSON envelope");
    assert_eq!(envelope["schemaVersion"], 1, "{command}");
    assert_eq!(envelope["ok"], true, "{command}");
    let data = &envelope["data"];
    assert!(
        data.get("output").is_none(),
        "{command}: stringly data.output payload is forbidden"
    );
    data.clone()
}

pub async fn connect_client(profile: &Path) -> AuthenticatedRuntimeClient {
    LocalRuntimeProfile::load(profile)
        .expect("load runtime profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("connect runtime client")
}

pub fn command_identity() -> CommandIdentity {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string()).expect("command identity")
}

/// Seeds project → workspace → conversation through the public client so the
/// atomic task run submit has real aggregate roots to reference.
pub async fn seed_conversation(client: &AuthenticatedRuntimeClient) -> (CanonicalId, CanonicalId) {
    let project_id = CanonicalId::now_v7();
    let workspace_id = CanonicalId::now_v7();
    let conversation_id = CanonicalId::now_v7();
    client
        .create_project(
            CreateProjectRequest::new(command_identity(), project_id, "CLI task test project")
                .expect("create project request"),
        )
        .await
        .expect("create test project");
    client
        .create_workspace(
            CreateWorkspaceRequest::new(
                command_identity(),
                project_id,
                workspace_id,
                "CLI task test workspace",
            )
            .expect("create workspace request"),
        )
        .await
        .expect("create test workspace");
    client
        .create_conversation(CreateConversationRequest::new(
            command_identity(),
            conversation_id,
            workspace_id,
            ConversationContextScope::Workspace,
        ))
        .await
        .expect("create test conversation");
    (conversation_id, workspace_id)
}

pub async fn submit_run(
    client: &AuthenticatedRuntimeClient,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
) -> TaskRunSubmitAcknowledgement {
    client
        .submit_task_run(SubmitTaskRunRequest::new(
            command_identity(),
            conversation_id,
            workspace_id,
        ))
        .await
        .expect("atomic task run submit")
}
