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

include!("bundled_runtime_parts/connect.rs");
include!("bundled_runtime_parts/monitor.rs");
include!("bundled_runtime_parts/lifecycle.rs");

#[cfg(test)]
mod tests {
    include!("bundled_runtime_parts/tests.rs");
}
