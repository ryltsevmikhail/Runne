#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::error::DaemonError;
use gocode_runtime_client::CanonicalId;
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

    let created = run_cli([
        "--profile",
        profile.to_str().expect("profile path"),
        "conversation",
        "create",
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
        "GOCODE local response: hello\n"
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
            r#"{{"schemaVersion":1,"profileId":"gocode-ui-client/1","schemaHash":"{marker}","endpoint":"http://127.0.0.1:9","tokenPath":"/tmp/{marker}"}}"#
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
    ])
    .await;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert_eq!(stderr, "local runtime profile is incompatible\n");
    assert!(!stderr.contains(marker));
    assert!(!stderr.contains(profile.to_str().expect("profile path")));
}

async fn run_cli<const N: usize>(arguments: [&str; N]) -> std::process::Output {
    let executable = env!("CARGO_BIN_EXE_gocode");
    let arguments = arguments.map(str::to_owned);
    tokio::task::spawn_blocking(move || Command::new(executable).args(arguments).output())
        .await
        .expect("join CLI")
        .expect("run CLI")
}
