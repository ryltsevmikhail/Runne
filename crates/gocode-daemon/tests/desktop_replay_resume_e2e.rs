#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use gocode_app_core::{AppCore, RuntimeAvailability};
use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_runtime_client::{LocalRuntimeConnectError, LocalRuntimeProfile, RuntimeTransportError};
use rusqlite::Connection;

const CHILD_MODE: &str = "GOCODE_DESKTOP_REPLAY_CHILD";
const CHILD_DB_PATH: &str = "GOCODE_DESKTOP_REPLAY_DB_PATH";
const CHILD_KEY_PATH: &str = "GOCODE_DESKTOP_REPLAY_KEY_PATH";
const CHILD_BIND: &str = "GOCODE_DESKTOP_REPLAY_BIND";
const CHILD_STOP_PATH: &str = "GOCODE_DESKTOP_REPLAY_STOP_PATH";

#[derive(Clone, Debug)]
struct ObservedSessionIdentity {
    authority: String,
    principal: String,
    lineage: String,
    instance: String,
    generation: u64,
    session: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalProjectionState {
    payload: Vec<u8>,
    cursor: String,
    event_sequence: i64,
    generation: i64,
    projection_revision: i64,
}

struct ChildDaemon {
    child: Option<Child>,
    stop_path: PathBuf,
}

impl ChildDaemon {
    fn start(
        database_path: &Path,
        replay_key_path: &Path,
        stop_path: &Path,
        bind: &str,
        profile_path: &Path,
        minimum_generation: u64,
    ) -> Self {
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("daemon_child_process")
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_MODE, "1")
            .env(CHILD_DB_PATH, database_path)
            .env(CHILD_KEY_PATH, replay_key_path)
            .env(CHILD_BIND, bind)
            .env(CHILD_STOP_PATH, stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start daemon child process");
        let daemon = Self {
            child: Some(child),
            stop_path: stop_path.to_path_buf(),
        };
        wait_for_profile(profile_path, minimum_generation);
        daemon
    }

    fn stop(mut self) {
        std::fs::write(&self.stop_path, b"stop").expect("request daemon shutdown");
        let mut child = self.child.take().expect("daemon child");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().expect("wait for daemon child") {
                assert!(status.success(), "daemon child did not stop cleanly");
                return;
            }
            assert!(Instant::now() < deadline, "daemon child shutdown timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildDaemon {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
#[ignore = "launched only by the real-process E2E parent"]
fn daemon_child_process() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }
    let database_path = required_child_path(CHILD_DB_PATH);
    let replay_key_path = required_child_path(CHILD_KEY_PATH);
    let stop_path = required_child_path(CHILD_STOP_PATH);
    let bind = std::env::var(CHILD_BIND).expect("child bind address");
    let runtime_root = database_path
        .parent()
        .and_then(Path::parent)
        .expect("runtime root");
    let mut defaults = BuiltInDefaults::new(runtime_root);
    defaults.db_path = database_path.display().to_string();
    defaults.replay_integrity_key_path = replay_key_path.display().to_string();
    defaults.http_bind = bind;
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let runtime = tokio::runtime::Runtime::new().expect("child Tokio runtime");
    runtime
        .block_on(async move {
            let application = DaemonApplication::start(&config).await?;
            application
                .run(async {
                    loop {
                        if stop_path.exists() {
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
        })
        .expect("run child daemon application");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_resume_reapplies_unacknowledged_duplicate_once() {
    let directory = tempfile::tempdir().expect("owner-only temporary directory");
    set_owner_only(directory.path());
    let runtime_root = directory.path().join("runtime");
    let daemon_directory = runtime_root.join("gocode-daemon");
    std::fs::create_dir_all(&daemon_directory).expect("create daemon directory");
    set_owner_only(&runtime_root);
    set_owner_only(&daemon_directory);
    let daemon_database = daemon_directory.join("event-log.db");
    let replay_key_path = daemon_directory.join("replay-integrity.key");
    let profile_path = daemon_directory.join("client-profile.json");
    let first_stop = directory.path().join("first.stop");

    let first_daemon = ChildDaemon::start(
        &daemon_database,
        &replay_key_path,
        &first_stop,
        "127.0.0.1:0",
        &profile_path,
        1,
    );
    let first_profile = profile_value(&profile_path);
    assert_eq!(first_profile["schemaVersion"], 2);
    assert_eq!(
        first_profile["transportProfileId"],
        "gocode-local-runtime/2"
    );
    let first_endpoint = endpoint_address(&first_profile);
    let stale_profile_path = directory.path().join("stale-client-profile.json");
    std::fs::copy(&profile_path, &stale_profile_path).expect("preserve stale profile");
    let first_identity = connect_identity(&profile_path).await;

    let desktop_database = directory.path().join("desktop.sqlite3");
    let project_path = directory.path().join("project");
    std::fs::create_dir(&project_path).expect("create project");
    let first_core = AppCore::open_with_runtime_profile(&desktop_database, profile_path.clone())
        .expect("open first desktop core");
    let project = first_core
        .open_local_project(&project_path)
        .expect("open local project");
    assert_eq!(
        first_core.connect_runtime().await.expect("connect runtime"),
        RuntimeAvailability::Live
    );
    let opened = first_core
        .open_project_conversation(project.id)
        .await
        .expect("create conversation");
    assert_eq!(opened.stream_version, 1);
    assert!(opened.messages.is_empty());

    install_ack_failure_after_inclusive_duplicate(&daemon_database);
    let error = first_core
        .send_project_message(project.id, "hello")
        .await
        .expect_err("server acknowledgement is forced to fail");
    assert_eq!(error.to_string(), "runtime is unavailable");
    assert_eq!(
        first_core.bootstrap().expect("closed bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    let interrupted = local_projection_state(&desktop_database);
    assert_eq!(interrupted.event_sequence, 2);
    let interrupted_payload: serde_json::Value =
        serde_json::from_slice(&interrupted.payload).expect("interrupted projection JSON");
    assert_eq!(
        interrupted_payload["messages"]
            .as_array()
            .expect("interrupted messages")
            .len(),
        1
    );
    assert_eq!(
        interrupted_payload["messages"][0]["role"],
        serde_json::json!("user")
    );
    assert!(
        daemon_has_unacknowledged_delivery(&daemon_database, first_identity.generation),
        "the child daemon must retain a delivery beyond its acknowledged position"
    );
    drop(first_core);
    first_daemon.stop();
    remove_ack_failure(&daemon_database);

    let counterfeit = tokio::net::TcpListener::bind(first_endpoint)
        .await
        .expect("bind counterfeit listener");
    let counterfeit_task = tokio::spawn(async move {
        if let Ok((stream, _)) = counterfeit.accept().await {
            drop(stream);
        }
    });
    let counterfeit_core =
        AppCore::open_with_runtime_profile(&desktop_database, stale_profile_path.clone())
            .expect("open counterfeit client");
    assert!(counterfeit_core.connect_runtime().await.is_err());
    assert_eq!(
        counterfeit_core
            .bootstrap()
            .expect("counterfeit bootstrap")
            .runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(
        local_projection_state(&desktop_database),
        interrupted,
        "counterfeit transport must not mutate the prior projection or cursor"
    );
    counterfeit_task.await.expect("counterfeit listener task");
    drop(counterfeit_core);

    let second_stop = directory.path().join("second.stop");
    let second_daemon = ChildDaemon::start(
        &daemon_database,
        &replay_key_path,
        &second_stop,
        &first_endpoint.to_string(),
        &profile_path,
        first_identity.generation + 1,
    );
    assert!(matches!(
        LocalRuntimeProfile::load(&stale_profile_path)
            .expect("stale profile shape")
            .connect(Duration::from_secs(5))
            .await,
        Err(LocalRuntimeConnectError::Transport(
            RuntimeTransportError::PeerIdentityMismatch
        ))
    ));
    let stale_core = AppCore::open_with_runtime_profile(&desktop_database, stale_profile_path)
        .expect("open stale desktop core");
    assert!(stale_core.connect_runtime().await.is_err());
    assert_eq!(
        stale_core.bootstrap().expect("stale bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(
        local_projection_state(&desktop_database),
        interrupted,
        "stale peer identity must not mutate the prior projection or cursor"
    );
    drop(stale_core);

    let second_identity = connect_identity(&profile_path).await;
    assert_eq!(second_identity.authority, first_identity.authority);
    assert_eq!(second_identity.principal, first_identity.principal);
    assert_eq!(second_identity.lineage, first_identity.lineage);
    assert_ne!(second_identity.instance, first_identity.instance);
    assert!(second_identity.generation > first_identity.generation);
    assert_ne!(second_identity.session, first_identity.session);

    let reopened = AppCore::open_with_runtime_profile(&desktop_database, profile_path)
        .expect("reopen desktop core");
    assert_eq!(
        reopened.connect_runtime().await.expect("reconnect runtime"),
        RuntimeAvailability::Live
    );
    let restored = reopened
        .open_project_conversation(project.id)
        .await
        .expect("resume conversation");
    assert_eq!(restored.stream_version, 3);
    assert_eq!(restored.messages.len(), 2);
    assert_eq!(
        restored
            .messages
            .iter()
            .filter(|message| message.role == "user" && message.text == "hello")
            .count(),
        1
    );
    assert_eq!(
        restored
            .messages
            .iter()
            .filter(|message| {
                message.role == "assistant" && message.text == "GOCODE local response: hello"
            })
            .count(),
        1
    );
    let message_ids = restored
        .messages
        .iter()
        .map(|message| message.message_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(message_ids.len(), restored.messages.len());
    let completed = local_projection_state(&desktop_database);
    assert_eq!(completed.event_sequence, 3);
    assert!(completed.projection_revision > interrupted.projection_revision);
    assert!(completed.generation > interrupted.generation);
    assert!(
        daemon_latest_cursor_is_acknowledged(&daemon_database, second_identity.generation),
        "the resumed cursor must be acknowledged by the restarted daemon"
    );
    second_daemon.stop();
}

fn required_child_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("required child path"))
}

fn wait_for_profile(profile_path: &Path, minimum_generation: u64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(bytes) = std::fs::read(profile_path)
            && let Ok(profile) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && profile["launchGeneration"].as_u64().unwrap_or_default() >= minimum_generation
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon profile publication timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn profile_value(profile_path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(profile_path).expect("read profile"))
        .expect("profile JSON")
}

fn endpoint_address(profile: &serde_json::Value) -> SocketAddr {
    profile["endpoint"]
        .as_str()
        .and_then(|endpoint| endpoint.strip_prefix("https://"))
        .expect("HTTPS loopback endpoint")
        .parse()
        .expect("socket address")
}

async fn connect_identity(profile_path: &Path) -> ObservedSessionIdentity {
    let client = LocalRuntimeProfile::load(profile_path)
        .expect("strict profile v2")
        .connect(Duration::from_secs(5))
        .await
        .expect("peer-authenticated session");
    let session = client.session_info();
    ObservedSessionIdentity {
        authority: session.authority_id.clone(),
        principal: session.principal_id.clone(),
        lineage: session.event_log_lineage_id.clone(),
        instance: session.daemon_instance_id.clone(),
        generation: session.launch_generation,
        session: session.session_id.clone(),
    }
}

fn install_ack_failure_after_inclusive_duplicate(database_path: &Path) {
    let connection = Connection::open(database_path).expect("open daemon database");
    connection
        .busy_timeout(Duration::from_secs(5))
        .expect("daemon database busy timeout");
    connection
        .execute_batch(
            "
            CREATE TRIGGER fail_replay_ack_after_duplicate
            BEFORE UPDATE OF last_acked_position ON _replay_subscriptions
            WHEN OLD.last_acked_position IS NOT NULL
             AND NEW.last_acked_position > OLD.last_acked_position
            BEGIN
                SELECT RAISE(FAIL, 'forced unacknowledged replay');
            END;
            ",
        )
        .expect("install replay acknowledgement fault");
}

fn remove_ack_failure(database_path: &Path) {
    Connection::open(database_path)
        .expect("open daemon database")
        .execute_batch("DROP TRIGGER fail_replay_ack_after_duplicate;")
        .expect("remove replay acknowledgement fault");
}

fn local_projection_state(database_path: &Path) -> LocalProjectionState {
    Connection::open(database_path)
        .expect("open desktop database")
        .query_row(
            "
            SELECT projections.payload,
                   replay_cursors.applied_cursor,
                   replay_cursors.event_sequence,
                   replay_cursors.generation,
                   projections.projection_revision
            FROM projections
            JOIN replay_cursors USING (
                runtime_authority,
                principal,
                lineage,
                scope
            )
            ",
            [],
            |row| {
                Ok(LocalProjectionState {
                    payload: row.get(0)?,
                    cursor: row.get(1)?,
                    event_sequence: row.get(2)?,
                    generation: row.get(3)?,
                    projection_revision: row.get(4)?,
                })
            },
        )
        .expect("one desktop projection and cursor")
}

fn daemon_has_unacknowledged_delivery(database_path: &Path, generation: u64) -> bool {
    let generation = i64::try_from(generation).expect("generation range");
    Connection::open(database_path)
        .expect("open daemon database")
        .query_row(
            "
            SELECT EXISTS (
                SELECT 1
                FROM _replay_subscriptions
                WHERE session_generation = ?1
                  AND last_delivered_position IS NOT NULL
                  AND last_acked_position IS NOT NULL
                  AND last_delivered_position > last_acked_position
            )
            ",
            [generation],
            |row| row.get(0),
        )
        .expect("read interrupted replay session")
}

fn daemon_latest_cursor_is_acknowledged(database_path: &Path, generation: u64) -> bool {
    let generation = i64::try_from(generation).expect("generation range");
    Connection::open(database_path)
        .expect("open daemon database")
        .query_row(
            "
            SELECT EXISTS (
                SELECT 1
                FROM _replay_subscriptions
                WHERE session_generation = ?1
                  AND last_delivered_position IS NOT NULL
                  AND last_acked_position IS NOT NULL
                  AND last_delivered_position = last_acked_position
                  AND state = 'live'
            )
            ",
            [generation],
            |row| row.get(0),
        )
        .expect("read resumed replay session")
}

fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(path)
            .expect("temporary directory metadata")
            .permissions()
            .mode()
            & 0o077,
        0
    );
}

fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set owner-only directory permissions");
    assert_owner_only(path);
}
