#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use gocode_app_core::{AppCore, RuntimeAvailability};
use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::error::DaemonError;
use tokio::sync::oneshot;

#[path = "support/owner_private.rs"]
mod owner_private;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_host_restores_the_same_authoritative_conversation_after_restart() {
    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = DaemonApplication::start(&config)
        .await
        .expect("start daemon");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    let runtime_profile =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    let database_path = directory.path().join("desktop.sqlite3");
    let project_path = directory.path().join("project");
    std::fs::create_dir(&project_path).expect("create project");

    let first = AppCore::open_with_runtime_profile(&database_path, runtime_profile.clone())
        .expect("open desktop core");
    let project = first
        .open_local_project(&project_path)
        .expect("open local project");
    assert_eq!(
        first.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Unconfigured
    );
    assert_eq!(
        first.connect_runtime().await.expect("connect runtime"),
        RuntimeAvailability::Live
    );

    let opened = first
        .open_project_conversation(project.id)
        .await
        .expect("open conversation");
    assert_eq!(opened.stream_version, 1);
    assert!(opened.messages.is_empty());

    let generated = first
        .send_project_message(project.id, "hello")
        .await
        .expect("send message");
    assert_eq!(generated.conversation_id, opened.conversation_id);
    assert_eq!(generated.stream_version, 3);
    assert_eq!(generated.messages.len(), 2);
    assert_eq!(generated.messages[0].role, "user");
    assert_eq!(generated.messages[0].text, "hello");
    assert_eq!(generated.messages[1].role, "assistant");
    assert_eq!(generated.messages[1].text, "GOCODE local response: hello");
    drop(first);

    let reopened = AppCore::open_with_runtime_profile(&database_path, runtime_profile)
        .expect("reopen desktop core");
    assert_eq!(
        reopened.connect_runtime().await.expect("reconnect runtime"),
        RuntimeAvailability::Live
    );
    let restored = reopened
        .open_project_conversation(project.id)
        .await
        .expect("restore conversation");
    assert_eq!(restored, generated);

    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");

    assert!(
        reopened.connect_runtime().await.is_err(),
        "a retry must revalidate the current daemon profile instead of trusting a stale client"
    );
    assert_eq!(
        reopened.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
}
