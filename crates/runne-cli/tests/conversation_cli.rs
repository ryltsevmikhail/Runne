#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_runtime_client::{
    CanonicalId, CommandIdentity, CreateProjectRequest, CreateWorkspaceRequest, LocalRuntimeProfile,
};
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_creates_sends_and_reads_a_conversation_through_the_real_daemon() {
    let directory = tempfile::tempdir().expect("temp directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure temp directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = DaemonApplication::start(&config)
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
    let workspace_id = seed_workspace(&profile).await;
    let workspace_id = workspace_id.to_string();

    let created = run_cli([
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "create",
        "--workspace-id",
        &workspace_id,
    ])
    .await;
    assert!(
        created.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(created.stderr.is_empty(), "success stderr must stay empty");
    let conversation_id = String::from_utf8(created.stdout)
        .expect("UTF-8 create output")
        .trim()
        .to_owned();
    CanonicalId::parse(&conversation_id).expect("CLI prints one Conversation UUID");

    let generated = run_cli([
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "send",
        "--conversation-id",
        &conversation_id,
        "--expected-version",
        "1",
        "--text",
        "hello",
    ])
    .await;
    assert!(
        generated.status.success(),
        "send failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert_eq!(
        String::from_utf8(generated.stdout).expect("UTF-8 assistant output"),
        "Runne local response: hello\n"
    );
    assert!(
        generated.stderr.is_empty(),
        "success stderr must stay empty"
    );

    let messages = run_cli([
        "--format",
        "json",
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "messages",
        "--conversation-id",
        &conversation_id,
    ])
    .await;
    assert!(
        messages.status.success(),
        "messages failed: {}",
        String::from_utf8_lossy(&messages.stderr)
    );
    let messages = parse_messages_output(&messages);
    assert_eq!(messages["conversationId"], conversation_id);
    assert_eq!(messages["streamVersion"], 3);
    assert_eq!(messages["messages"].as_array().expect("messages").len(), 2);
    assert_eq!(messages["messages"][0]["role"], "user");
    assert_eq!(messages["messages"][1]["role"], "assistant");

    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");
}

fn parse_messages_output(output: &std::process::Output) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("messages JSON");
    assert_eq!(envelope["schemaVersion"], 1);
    assert_eq!(envelope["ok"], true);
    serde_json::from_str(
        envelope["data"]["output"]
            .as_str()
            .expect("messages JSON output"),
    )
    .expect("messages JSON payload")
}

#[tokio::test]
async fn cli_rejects_profile_v1_without_http_fallback_or_secret_disclosure() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile = directory.path().join("legacy-profile.json");
    let marker = "legacy-secret-marker";
    std::fs::write(
        &profile,
        format!(
            r#"{{"schemaVersion":1,"profileId":"runne-ui-client/1","schemaHash":"{marker}","endpoint":"http://127.0.0.1:9","tokenPath":"/tmp/{marker}"}}"#
        ),
    )
    .expect("write legacy profile");
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600))
        .expect("secure profile");

    let output = run_cli([
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "create",
        "--workspace-id",
        "018f2e3a-7000-7000-8000-000000000001",
    ])
    .await;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert_eq!(stderr, "local runtime profile is incompatible\n");
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains(profile.to_str().expect("profile path")));
}

#[tokio::test]
async fn cli_requires_workspace_id_for_conversation_create() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile = directory.path().join("profile.json");
    std::fs::write(&profile, r"{}").expect("write placeholder profile");

    let output = run_cli([
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "create",
    ])
    .await;

    assert_eq!(output.status.code(), Some(2), "usage error exit code");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(stderr.contains("Usage:"), "usage text expected: {stderr}");
}

async fn run_cli<const N: usize>(arguments: [&str; N]) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_runne");
    let arguments = arguments.map(str::to_owned);
    tokio::task::spawn_blocking(move || Command::new(executable).args(arguments).output())
        .await
        .expect("join CLI")
        .expect("run CLI")
}

async fn seed_workspace(profile: &Path) -> CanonicalId {
    let client = LocalRuntimeProfile::load(profile)
        .expect("load runtime profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("connect runtime client");
    let project_id = CanonicalId::now_v7();
    let workspace_id = CanonicalId::now_v7();
    client
        .create_project(
            CreateProjectRequest::new(
                command_identity(),
                project_id,
                "CLI conversation test project",
            )
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
                "CLI conversation test workspace",
            )
            .expect("create workspace request"),
        )
        .await
        .expect("create test workspace");
    workspace_id
}

fn command_identity() -> CommandIdentity {
    let command_id = CanonicalId::now_v7();
    CommandIdentity::new(command_id, command_id.to_string()).expect("command identity")
}
