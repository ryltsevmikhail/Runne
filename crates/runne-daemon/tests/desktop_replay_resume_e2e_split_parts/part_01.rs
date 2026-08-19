use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use runne_app_core::{AppCore, RuntimeAvailability};
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest,
};
use runne_domain::timestamp::Timestamp;
use runne_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, GenerateTextRequest,
    LocalRuntimeConnectError, LocalRuntimeProfile, ReplayAggregateKind, ReplayIdentityTracker,
    ReplayLiveSession, ReplayRecoveryDisposition, ReplayScope, ReplayStreamEvent,
    RuntimeTransportError,
};
use runne_store::codec::{ConversationEventCodec, StoreCodec};
use runne_store::integrity::compute_integrity_digest_v2_with_global_position;
use runne_secure_store::SecureStore;
use rusqlite::Connection;
use tokio::sync::{Mutex, MutexGuard};

const CHILD_MODE: &str = "RUNNE_DESKTOP_REPLAY_CHILD";
const CHILD_DB_PATH: &str = "RUNNE_DESKTOP_REPLAY_DB_PATH";
const CHILD_KEY_PATH: &str = "RUNNE_DESKTOP_REPLAY_KEY_PATH";
const CHILD_BIND: &str = "RUNNE_DESKTOP_REPLAY_BIND";
const CHILD_STOP_PATH: &str = "RUNNE_DESKTOP_REPLAY_STOP_PATH";
static PROCESS_E2E_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

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
    let stop_requested = stop_path.clone();
    let result = runtime.block_on(async move {
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
    });
    match result {
        Ok(()) => {}
        Err(DaemonError::Bootstrap(message))
            if stop_requested.exists() && message == "runtime shutdown timeout" =>
        {
            // Replay tests may deliberately leave a live HTTP stream open. The
            // production daemon correctly reports the bounded drain timeout;
            // for this child-process harness, completed termination is enough.
        }
        Err(error) => panic!("run child daemon application: {error:?}"),
    }
}
