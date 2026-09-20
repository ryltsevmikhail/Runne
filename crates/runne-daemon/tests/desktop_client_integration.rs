#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use runne_app_core::RuntimeAvailability;
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_runtime_client::CanonicalId;
use runne_secure_store::SecureStore;
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
    let security_profile = [0xD3; 32];
    let secure: std::sync::Arc<dyn SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(security_profile),
    );
    let project_path = directory.path().join("project");
    std::fs::create_dir(&project_path).expect("create project");

    let first = runne_app_core::test_support::open_anchored_external_local_core(
        &database_path,
        runtime_profile.clone(),
        std::sync::Arc::clone(&secure),
        security_profile,
    )
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
    prepare_canonical_conversation_workspace(&first, project).await;
    // NM-06 context-scope contract: the project-scoped conversation delivers
    // only through an explicit trust record (the former never-governed allow
    // is removed).
    grant_daemon_project_trust(std::path::Path::new(&config.db_path));

    let opened = first
        .open_project_conversation(project)
        .await
        .expect("open conversation");
    assert_eq!(opened.stream_version, 1);
    assert!(opened.messages.is_empty());

    let generated = first
        .send_project_message(project, "hello")
        .await
        .expect("send message");
    assert_eq!(generated.conversation_id, opened.conversation_id);
    assert_eq!(generated.stream_version, 3);
    assert_eq!(generated.messages.len(), 2);
    assert_eq!(generated.messages[0].role, "user");
    assert_eq!(generated.messages[0].text, "hello");
    assert_eq!(generated.messages[1].role, "assistant");
    assert_eq!(generated.messages[1].text, "Runne local response: hello");
    drop(first);

    let reopened = runne_app_core::test_support::open_anchored_external_local_core(
        &database_path,
        runtime_profile,
        secure,
        security_profile,
    )
    .expect("reopen desktop core");
    assert_eq!(
        reopened.connect_runtime().await.expect("reconnect runtime"),
        RuntimeAvailability::Live
    );
    let restored = reopened
        .open_project_conversation(project)
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

async fn prepare_canonical_conversation_workspace(
    core: &runne_app_core::AppCore,
    local_project_id: i64,
) {
    let runtime_project_id = CanonicalId::now_v7();
    let workspace_id = CanonicalId::now_v7();
    core.create_runtime_project(runtime_project_id, "Desktop fixture".into())
        .await
        .expect("create canonical project");
    core.create_runtime_workspace(runtime_project_id, workspace_id, "Desktop fixture".into())
        .await
        .expect("create canonical workspace");
    runne_app_core::test_support::install_unbound_conversation_reference_for_test(
        core,
        local_project_id,
        CanonicalId::now_v7(),
        workspace_id,
    )
    .expect("install canonical conversation reference");
}

fn grant_daemon_project_trust(db_path: &std::path::Path) {
    use runne_application::project_trust::{
        ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus,
    };
    let connection = rusqlite::Connection::open(db_path).expect("open daemon database");
    let authority = runne_store::schema::read_authority_id(&connection)
        .expect("read authority id")
        .expect("authority id present");
    let project_id: [u8; 16] = connection
        .query_row("SELECT project_id FROM projects LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("canonical project row");
    drop(connection);
    let store = runne_store::ProjectTrustStore::open(db_path, authority)
        .expect("open daemon trust sidecar");
    let project = ProjectTrustProjectId::from_bytes(project_id);
    let record = store.load(project).expect("trust record");
    store
        .commit(project, ProjectTrustStatus::Trusted, 0, record.token())
        .expect("grant project trust");
}
