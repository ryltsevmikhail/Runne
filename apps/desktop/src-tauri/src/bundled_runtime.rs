//! Native host integration for the protected bundled-runtime supervisor.
//!
//! This module exposes no transport material to Tauri commands. It connects
//! the one-time protected profile directly to `AppCore`, monitors only the
//! proven-owned child, and maps every failure to a closed renderer-safe code.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{OwnedRuntimeLifecycle, RuntimeConnectionFuture};
use gocode_app_core::{
    AppCore, AppCoreError, BundledRuntimeActivationLease, RuntimeAvailability, RuntimeFailureCode,
};
use gocode_platform_desktop::{
    BundledRuntimeLifecycleState, BundledRuntimeStopDisposition, DevelopmentBundledRuntimeLauncher,
    PROTECTED_BUNDLED_SESSION_RENEW_AFTER, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeSupervisor, discover_bundled_runtime,
};

const BUNDLED_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Closed host-side result of the explicit-quit shutdown policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledShutdownOutcome {
    Graceful,
    Forced,
    Incomplete,
}

struct RuntimeOperationFence {
    stopping: AtomicBool,
    operation: tokio::sync::Mutex<()>,
}

impl RuntimeOperationFence {
    const fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            operation: tokio::sync::Mutex::const_new(()),
        }
    }

    async fn enter(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if self.is_stopping() {
            return None;
        }
        let guard = self.operation.lock().await;
        if self.is_stopping() {
            return None;
        }
        Some(guard)
    }

    fn begin_shutdown(&self) -> bool {
        !self.stopping.swap(true, Ordering::AcqRel)
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn wait_for_idle(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.operation.blocking_lock()
    }
}

#[derive(Debug)]
struct ProtectedSessionRenewalSchedule {
    renew_after: Duration,
    deadline: Option<Instant>,
}

impl ProtectedSessionRenewalSchedule {
    const fn new(renew_after: Duration) -> Self {
        Self {
            renew_after,
            deadline: None,
        }
    }

    fn arm(&mut self, now: Instant) {
        self.deadline = now.checked_add(self.renew_after);
    }

    const fn clear(&mut self) {
        self.deadline = None;
    }

    fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_none_or(|deadline| now >= deadline)
    }
}

/// Connects `AppCore` to one concrete protected bundled-runtime supervisor.
pub struct BundledRuntimeController {
    core: Arc<AppCore>,
    supervisor: Arc<Mutex<ProtectedBundledRuntimeSupervisor>>,
    operation_fence: RuntimeOperationFence,
    renewal_schedule: Mutex<ProtectedSessionRenewalSchedule>,
    shutdown_outcome: Mutex<Option<BundledShutdownOutcome>>,
}

impl BundledRuntimeController {
    /// Discovers and pins the colocated daemon before creating its supervisor.
    ///
    /// # Errors
    ///
    /// Returns one closed renderer-safe code. No external runtime fallback is
    /// attempted.
    pub fn discover(
        core: Arc<AppCore>,
        desktop_executable: &std::path::Path,
        runtime_root: &std::path::Path,
    ) -> Result<Arc<Self>, RuntimeFailureCode> {
        let executable =
            discover_bundled_runtime(desktop_executable).map_err(map_protected_failure)?;
        let spec = ProtectedBundledRuntimeLaunchSpec::new(&executable, runtime_root)
            .map_err(map_protected_failure)?;
        let supervisor =
            ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
        Ok(Arc::new(Self {
            core,
            supervisor: Arc::new(Mutex::new(supervisor)),
            operation_fence: RuntimeOperationFence::new(),
            renewal_schedule: Mutex::new(ProtectedSessionRenewalSchedule::new(
                PROTECTED_BUNDLED_SESSION_RENEW_AFTER,
            )),
            shutdown_outcome: Mutex::new(None),
        }))
    }

    /// Starts the bounded monitor on the native async runtime.
    pub fn spawn_monitor(self: &Arc<Self>) {
        let controller = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            controller.monitor_loop().await;
        });
    }

    #[must_use]
    pub fn shutdown_outcome(&self) -> Option<BundledShutdownOutcome> {
        self.shutdown_outcome
            .lock()
            .map_or(Some(BundledShutdownOutcome::Incomplete), |outcome| *outcome)
    }

    async fn connect(&self) -> Result<RuntimeAvailability, AppCoreError> {
        let Some(_operation) = self.operation_fence.enter().await else {
            return Err(AppCoreError::RuntimeUnavailable);
        };
        match self.supervisor_state()? {
            BundledRuntimeLifecycleState::Absent => self.start_fresh(false).await,
            BundledRuntimeLifecycleState::Stopped
            | BundledRuntimeLifecycleState::FailedStart
            | BundledRuntimeLifecycleState::Exhausted => self.start_fresh(true).await,
            BundledRuntimeLifecycleState::Ready => {
                let availability = self.core.bootstrap()?.runtime;
                if matches!(
                    availability,
                    RuntimeAvailability::Live | RuntimeAvailability::ResyncRequired
                ) {
                    Ok(availability)
                } else {
                    Err(AppCoreError::RuntimeUnavailable)
                }
            }
            BundledRuntimeLifecycleState::Handshaking
            | BundledRuntimeLifecycleState::Backoff
            | BundledRuntimeLifecycleState::ValidatingBinary
            | BundledRuntimeLifecycleState::Spawning
            | BundledRuntimeLifecycleState::Disconnected
            | BundledRuntimeLifecycleState::Probing
            | BundledRuntimeLifecycleState::Crashed
            | BundledRuntimeLifecycleState::Stopping
            | BundledRuntimeLifecycleState::Incompatible
            | BundledRuntimeLifecycleState::IdentityMismatch
            | BundledRuntimeLifecycleState::OwnershipConflict => {
                Err(AppCoreError::RuntimeUnavailable)
            }
        }
    }

    async fn start_fresh(&self, restarting: bool) -> Result<RuntimeAvailability, AppCoreError> {
        self.clear_renewal_schedule()?;
        let lease = if restarting {
            self.core.begin_bundled_runtime_restart().await?
        } else {
            self.core.begin_bundled_runtime_start().await?
        };
        if let Err(error) = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::start)
            .await
        {
            self.core
                .mark_bundled_runtime_failed(map_protected_failure(error))
                .await?;
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.connect_pending_profile(lease).await
    }

    async fn connect_pending_profile(
        &self,
        lease: BundledRuntimeActivationLease,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        let profile = self
            .supervisor
            .lock()
            .map(|mut supervisor| supervisor.take_runtime_profile())
            .map_err(|_| AppCoreError::RuntimeUnavailable)?;
        let Some(profile) = profile else {
            self.core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await?;
            return Err(AppCoreError::RuntimeUnavailable);
        };
        let Ok(client) = profile.connect(BUNDLED_CLIENT_CONNECT_TIMEOUT).await else {
            return self
                .reject_current_client(RuntimeFailureCode::ProtectedReadinessRejected)
                .await;
        };
        let checked_client = client.clone();
        if let Err(error) = self
            .run_supervisor(move |supervisor| supervisor.record_client_ready(&checked_client))
            .await
        {
            return self
                .reject_current_client(map_protected_failure(error))
                .await;
        }
        if self.operation_fence.is_stopping() {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.arm_renewal_schedule()?;
        if self
            .core
            .install_bundled_runtime_client(lease, client)
            .await
            .is_err()
        {
            return self
                .reject_current_client(RuntimeFailureCode::ProtectedReadinessRejected)
                .await;
        }
        Ok(RuntimeAvailability::Live)
    }

    async fn reject_current_client(
        &self,
        failure: RuntimeFailureCode,
    ) -> Result<RuntimeAvailability, AppCoreError> {
        self.clear_renewal_schedule()?;
        let supervisor_result = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::record_client_failure)
            .await;
        let failure = supervisor_result
            .err()
            .map_or(failure, map_protected_failure);
        let terminal = matches!(
            failure,
            RuntimeFailureCode::BundledRestartExhausted
                | RuntimeFailureCode::BundledShutdownIncomplete
                | RuntimeFailureCode::UnsupportedPlatformBackend
        );
        if terminal {
            self.core.mark_bundled_runtime_failed(failure).await?;
        } else {
            self.core.mark_bundled_runtime_degraded(failure).await?;
        }
        Err(AppCoreError::RuntimeUnavailable)
    }

    async fn monitor_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(SUPERVISOR_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if self.operation_fence.is_stopping() {
                break;
            }
            self.monitor_once().await;
        }
    }

    async fn monitor_once(&self) {
        let Some(_operation) = self.operation_fence.enter().await else {
            return;
        };
        let Ok(before) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };
        let monitor_result = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::monitor)
            .await;
        let Ok(after) = self.supervisor_state() else {
            let _ = self
                .core
                .mark_bundled_runtime_failed(RuntimeFailureCode::ProtectedActivationUnavailable)
                .await;
            return;
        };

        if let Err(error) = monitor_result {
            let failure = map_protected_failure(error);
            if after == BundledRuntimeLifecycleState::Exhausted {
                let _ = self.core.mark_bundled_runtime_failed(failure).await;
            } else {
                let _ = self.core.mark_bundled_runtime_degraded(failure).await;
            }
            return;
        }

        match (before, after) {
            (BundledRuntimeLifecycleState::Ready, BundledRuntimeLifecycleState::Ready)
                if self.renewal_is_due().unwrap_or(true) =>
            {
                self.rotate_protected_session().await;
            }
            (
                BundledRuntimeLifecycleState::Ready | BundledRuntimeLifecycleState::Handshaking,
                BundledRuntimeLifecycleState::Backoff,
            ) => {
                let _ = self.clear_renewal_schedule();
                let _ = self.core.begin_bundled_runtime_restart().await;
            }
            (BundledRuntimeLifecycleState::Backoff, BundledRuntimeLifecycleState::Handshaking) => {
                let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
                    return;
                };
                let _ = self.connect_pending_profile(lease).await;
            }
            (_, BundledRuntimeLifecycleState::Exhausted) => {
                let _ = self
                    .core
                    .mark_bundled_runtime_failed(RuntimeFailureCode::BundledRestartExhausted)
                    .await;
            }
            _ => {}
        }
    }

    async fn rotate_protected_session(&self) {
        self.clear_renewal_schedule().ok();
        let Ok(lease) = self.core.begin_bundled_runtime_restart().await else {
            return;
        };
        if let Err(error) = self
            .run_supervisor(ProtectedBundledRuntimeSupervisor::queue_renewal_profile)
            .await
        {
            let _ = self
                .reject_current_client(map_protected_failure(error))
                .await;
            return;
        }
        let _ = self.connect_pending_profile(lease).await;
    }

    fn arm_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.arm(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn clear_renewal_schedule(&self) -> Result<(), AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|mut schedule| schedule.clear())
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn renewal_is_due(&self) -> Result<bool, AppCoreError> {
        self.renewal_schedule
            .lock()
            .map(|schedule| schedule.is_due(Instant::now()))
            .map_err(|_| AppCoreError::StateUnavailable)
    }

    fn supervisor_state(&self) -> Result<BundledRuntimeLifecycleState, AppCoreError> {
        self.supervisor
            .lock()
            .map(|supervisor| supervisor.state())
            .map_err(|_| AppCoreError::RuntimeUnavailable)
    }

    async fn run_supervisor<T, F>(&self, action: F) -> Result<T, ProtectedBundledRuntimeError>
    where
        T: Send + 'static,
        F: FnOnce(
                &mut ProtectedBundledRuntimeSupervisor,
            ) -> Result<T, ProtectedBundledRuntimeError>
            + Send
            + 'static,
    {
        let supervisor = Arc::clone(&self.supervisor);
        tokio::task::spawn_blocking(move || {
            let mut supervisor = supervisor
                .lock()
                .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
            action(&mut supervisor)
        })
        .await
        .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?
    }
}

impl OwnedRuntimeLifecycle for BundledRuntimeController {
    fn connect_runtime(&self) -> RuntimeConnectionFuture<'_> {
        Box::pin(self.connect())
    }

    fn stop_on_explicit_quit(&self) {
        if !self.operation_fence.begin_shutdown() {
            return;
        }
        let _operation = self.operation_fence.wait_for_idle();
        let core_fenced =
            tauri::async_runtime::block_on(self.core.fence_bundled_runtime_shutdown()).is_ok();
        let _ = self.clear_renewal_schedule();
        let stop_outcome = self
            .supervisor
            .lock()
            .map_err(|_| ProtectedBundledRuntimeError::ShutdownIncomplete)
            .and_then(|mut supervisor| supervisor.stop())
            .map_or(
                BundledShutdownOutcome::Incomplete,
                |disposition| match disposition {
                    BundledRuntimeStopDisposition::Graceful => BundledShutdownOutcome::Graceful,
                    BundledRuntimeStopDisposition::Forced => BundledShutdownOutcome::Forced,
                },
            );
        let outcome = if core_fenced {
            stop_outcome
        } else {
            BundledShutdownOutcome::Incomplete
        };
        if let Ok(mut recorded) = self.shutdown_outcome.lock() {
            *recorded = Some(outcome);
        }
    }
}

const fn map_protected_failure(error: ProtectedBundledRuntimeError) -> RuntimeFailureCode {
    match error {
        ProtectedBundledRuntimeError::UnsupportedPlatformBackend => {
            RuntimeFailureCode::UnsupportedPlatformBackend
        }
        ProtectedBundledRuntimeError::ExecutableUnavailable => {
            RuntimeFailureCode::BundledExecutableUnavailable
        }
        ProtectedBundledRuntimeError::ExecutableIdentityMismatch => {
            RuntimeFailureCode::BundledExecutableIdentityMismatch
        }
        ProtectedBundledRuntimeError::ReadinessTimeout
        | ProtectedBundledRuntimeError::OwnershipMismatch => {
            RuntimeFailureCode::ProtectedReadinessRejected
        }
        ProtectedBundledRuntimeError::RestartExhausted => {
            RuntimeFailureCode::BundledRestartExhausted
        }
        ProtectedBundledRuntimeError::ShutdownIncomplete => {
            RuntimeFailureCode::BundledShutdownIncomplete
        }
        ProtectedBundledRuntimeError::RuntimeRootUnavailable
        | ProtectedBundledRuntimeError::ActivationStateUnavailable
        | ProtectedBundledRuntimeError::ProtectedChannelUnavailable
        | ProtectedBundledRuntimeError::SpawnFailed
        | ProtectedBundledRuntimeError::InvalidState
        | ProtectedBundledRuntimeError::LaunchAuthority(_) => {
            RuntimeFailureCode::ProtectedActivationUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    use super::{ProtectedSessionRenewalSchedule, RuntimeOperationFence, map_protected_failure};
    use gocode_app_core::RuntimeFailureCode;
    use gocode_platform_desktop::ProtectedBundledRuntimeError;

    #[test]
    fn protected_failures_map_to_closed_renderer_codes() {
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::ExecutableUnavailable),
            RuntimeFailureCode::BundledExecutableUnavailable
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::OwnershipMismatch),
            RuntimeFailureCode::ProtectedReadinessRejected
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::RestartExhausted),
            RuntimeFailureCode::BundledRestartExhausted
        );
        assert_eq!(
            map_protected_failure(ProtectedBundledRuntimeError::UnsupportedPlatformBackend),
            RuntimeFailureCode::UnsupportedPlatformBackend
        );
    }

    #[test]
    fn protected_session_renewal_schedule_is_early_and_rearmable() {
        let now = Instant::now();
        let mut schedule = ProtectedSessionRenewalSchedule::new(Duration::from_millis(20));

        assert!(schedule.is_due(now));
        schedule.arm(now);
        assert!(!schedule.is_due(now + Duration::from_millis(19)));
        assert!(schedule.is_due(now + Duration::from_millis(20)));
        schedule.arm(now + Duration::from_millis(20));
        assert!(!schedule.is_due(now + Duration::from_millis(39)));
        assert!(schedule.is_due(now + Duration::from_millis(40)));
        schedule.clear();
        assert!(schedule.is_due(now));
    }

    #[test]
    fn shutdown_fence_waits_for_inflight_install_and_rejects_new_work() {
        let fence = Arc::new(RuntimeOperationFence::new());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_fence = Arc::clone(&fence);
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let operation = worker_fence.enter().await.expect("enter operation");
                entered_tx.send(()).expect("signal entered");
                release_rx.recv().expect("release operation");
                drop(operation);
            });
        });
        entered_rx.recv().expect("operation entered");

        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let shutdown_fence = Arc::clone(&fence);
        let shutdown = std::thread::spawn(move || {
            assert!(shutdown_fence.begin_shutdown());
            let _idle = shutdown_fence.wait_for_idle();
            shutdown_tx.send(()).expect("signal shutdown");
        });
        assert!(shutdown_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release_tx.send(()).expect("release operation");
        shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown acquires fence");
        worker.join().expect("worker");
        shutdown.join().expect("shutdown");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        assert!(runtime.block_on(fence.enter()).is_none());
        assert!(!fence.begin_shutdown());
    }
}
