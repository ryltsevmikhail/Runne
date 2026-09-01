use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use super::post_fence::spawn_pre_fence_enrollment_owner;
use super::{LivePostFenceAdmission, run_post_fence_branches};
use crate::bundled_runtime::test_only_live_enrollment_runtime;
use crate::provider_credential_enrollment::prepared::reap_guard::{
    ExactWriterCleanup, ExactWriterRecovery, RetainedWriterCleanup,
};
use crate::provider_credential_enrollment::{CredentialIntentIpc, CredentialIntentRegistry};
use crate::updater_status::enrollment::{
    test_only_current_enrollment_updater, test_only_expired_enrollment_updater,
};
use runne_api::{ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2};
use runne_platform_desktop::{SecureCredentialMaterial, SecureCredentialPromptDisposition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    FenceBegun,
    Transition,
    Connect,
    Install,
    PostHandoff,
}

#[tokio::test]
async fn pre_fence_owner_survives_command_cancellation_at_every_lifecycle_stage() {
    for cancel_at in [
        Stage::FenceBegun,
        Stage::Transition,
        Stage::Connect,
        Stage::Install,
        Stage::PostHandoff,
    ] {
        let stopped = Arc::new(AtomicUsize::new(0));
        let degraded = Arc::new(AtomicUsize::new(0));
        let stop = Arc::clone(&stopped);
        let degrade = Arc::clone(&degraded);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let work_release = Arc::clone(&release);
        let (result, completion) = spawn_pre_fence_enrollment_owner(
            move || async move {
                for stage in [
                    Stage::FenceBegun,
                    Stage::Transition,
                    Stage::Connect,
                    Stage::Install,
                    Stage::PostHandoff,
                ] {
                    events_tx.send(stage).expect("stage receiver");
                    if stage == cancel_at {
                        work_release.notified().await;
                    }
                }
                Err::<(), ()>(())
            },
            move || async move {
                stop.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                degrade.fetch_add(1, Ordering::SeqCst);
            },
            || (),
        );
        let command = tokio::spawn(result);
        loop {
            let reached = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
                .await
                .expect("owner stage timeout")
                .expect("owner stage");
            if reached == cancel_at {
                command.abort();
                release.notify_one();
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .expect("owner completion timeout")
            .expect("owner completion");
        let _ = command.await;
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert_eq!(degraded.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn blocking_worker_panic_is_outer_cleanup_once() {
    let stopped = Arc::new(AtomicUsize::new(0));
    let degraded = Arc::new(AtomicUsize::new(0));
    let stop = Arc::clone(&stopped);
    let degrade = Arc::clone(&degraded);
    let child = Arc::new(Mutex::new(
        std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("child"),
    ));
    let reaped = Arc::new(AtomicUsize::new(0));
    let worker_child = Arc::clone(&child);
    let worker_reaped = Arc::clone(&reaped);
    let (result, completion) = spawn_pre_fence_enrollment_owner(
        || async move {
            tauri::async_runtime::spawn_blocking(move || {
                let _writer = RetainedWriterCleanup::new(
                    ChildCleanup {
                        child: worker_child,
                        reaped: worker_reaped,
                    },
                    ExactWriterRecovery::new(),
                );
                panic!("injected transcript panic");
            })
            .await
            .map_err(|_| ())
        },
        move || async move {
            stop.fetch_add(1, Ordering::SeqCst);
            degrade.fetch_add(1, Ordering::SeqCst);
        },
        || (),
    );
    assert_eq!(result.await.expect("owner result"), Err(()));
    completion.wait().await.expect("owner completion");
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
    assert_eq!(degraded.load(Ordering::SeqCst), 1);
    assert_eq!(reaped.load(Ordering::SeqCst), 1);
    assert!(child.lock().expect("child").try_wait().unwrap().is_some());
}

struct ChildCleanup {
    child: Arc<Mutex<std::process::Child>>,
    reaped: Arc<AtomicUsize>,
}

impl ExactWriterCleanup for ChildCleanup {
    type Error = ();

    fn finish_exact(&mut self) -> Result<(), Self::Error> {
        self.reap()
    }

    fn abort_exact(&mut self) -> Result<(), Self::Error> {
        self.child.lock().map_err(|_| ())?.kill().map_err(|_| ())?;
        self.reap()
    }
}

impl ChildCleanup {
    fn reap(&self) -> Result<(), ()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if self
                .child
                .lock()
                .map_err(|_| ())?
                .try_wait()
                .map_err(|_| ())?
                .is_some()
            {
                self.reaped.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[tokio::test]
async fn exact_live_post_fence_branches_fail_closed_before_writer() {
    for fault in [
        LiveFault::MissingV3,
        LiveFault::ExpiredUpdater,
        LiveFault::FullRegistry,
    ] {
        let directory = tempfile::tempdir().expect("fixture directory");
        let supervisor = match fault {
            LiveFault::MissingV3 => {
                runne_platform_desktop::test_only_absent_enrollment_supervisor()
            }
            LiveFault::ExpiredUpdater | LiveFault::FullRegistry => {
                runne_platform_desktop::test_only_ready_v3_enrollment_supervisor()
            }
        };
        let mut runtime = test_only_live_enrollment_runtime(directory.path(), supervisor).await;
        let (runtime_lease, cleanup) = runtime.take_lease_with_cleanup();
        let updater = match fault {
            LiveFault::ExpiredUpdater => {
                test_only_expired_enrollment_updater(directory.path()).await
            }
            LiveFault::MissingV3 | LiveFault::FullRegistry => {
                test_only_current_enrollment_updater(directory.path()).await
            }
        };
        let registry = CredentialIntentRegistry::new(Duration::from_secs(1)).expect("registry");
        if fault == LiveFault::FullRegistry {
            fill_registry(&registry);
        }
        let writer_calls = Arc::new(AtomicUsize::new(0));
        let writer = Arc::clone(&writer_calls);
        let (result, completion) = spawn_pre_fence_enrollment_owner(
            move || async move {
                let result = run_post_fence_branches(LivePostFenceAdmission {
                    intents: &registry,
                    disposition: SecureCredentialPromptDisposition::Submitted(
                        SecureCredentialMaterial::new(b"credential".to_vec()).expect("material"),
                    ),
                    window: "main".into(),
                    request: pair_request(),
                    installed: updater.confirmed,
                    runtime: runtime_lease,
                    updater: updater.lease,
                    intent_session: None,
                });
                if result.is_ok() {
                    writer.fetch_add(1, Ordering::SeqCst);
                }
                result.map(|_| ())
            },
            move || async move { cleanup.abort().await },
            || super::DispatchFailure::Closed("provider_credential_exchange_rejected"),
        );
        assert!(result.await.expect("owner result").is_err());
        completion.wait().await.expect("owner completion");
        assert_eq!(writer_calls.load(Ordering::SeqCst), 0);
        assert!(runtime.cleanup_completed());
        drop(runtime);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LiveFault {
    MissingV3,
    ExpiredUpdater,
    FullRegistry,
}

fn pair_request() -> CredentialIntentIpc {
    CredentialIntentIpc {
        provider: ProviderCredentialProviderV2::OpenAi,
        action: ProviderCredentialEnrollmentActionV2::Pair,
        expected_revision: 7,
        renderer_generation: 3,
        verification_kind: None,
    }
}

fn fill_registry(registry: &CredentialIntentRegistry) {
    let now = Instant::now();
    while registry.pending_len() < 64 {
        registry
            .issue("occupied", 1, pair_request(), [8; 32], now)
            .expect("fill registry");
    }
}

#[test]
fn platform_enrollment_fixtures_are_dev_only_dependencies() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("desktop manifest");
    let production = manifest
        .split("[dev-dependencies]")
        .next()
        .expect("production dependency sections");
    assert!(!production.contains("runne-platform-desktop/test-support"));
    assert!(!production.contains("features = [\"test-support\"]"));
    let dev = manifest
        .split("[dev-dependencies]")
        .nth(1)
        .expect("dev dependencies");
    assert!(dev.contains("runne-platform-desktop"));
    assert!(dev.contains("\"test-support\""));
}
