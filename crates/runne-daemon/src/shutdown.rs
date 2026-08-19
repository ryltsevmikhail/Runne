//! Shutdown subsystem.
//!
//! Implements ADR-0018 graceful shutdown sequence:
//! - `RuntimeTaskSupervisor` — tracks all spawned tasks with active/completed counters.
//! - `graceful_shutdown` — fences admission, drains active tasks, commits quiesced.
//!
//! ## Design invariants
//!
//! 1. `register()` increments active; `Drop` of `TaskHandle` decrements active.
//! 2. `fence()` prevents new work via `is_fenced()` check.
//! 3. `drain()` waits for all active tasks with a timeout; timeout returns error.
//! 4. Forced shutdown (skip drain) is permissible; the fence is still set.

use std::collections::HashSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crate::error::DaemonError;

/// Tracks all spawned tasks and enforces the shutdown sequence.
#[derive(Debug)]
pub struct RuntimeTaskSupervisor {
    registered: Mutex<HashSet<u64>>,
    next_id: AtomicUsize,
    active: AtomicUsize,
    fence: AtomicBool,
    completed: AtomicUsize,
}

/// A handle that represents a registered task.
///
/// The task is tracked until this handle is dropped.
/// On drop, the supervisor's active count is decremented
/// and the completed count is incremented.
#[derive(Clone, Debug)]
pub struct TaskHandle {
    #[allow(dead_code)]
    id: u64,
    supervisor: Arc<RuntimeTaskSupervisor>,
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        self.supervisor.completed.fetch_add(1, Ordering::SeqCst);
        self.supervisor.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RuntimeTaskSupervisor {
    /// Create a new supervisor wrapped in `Arc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registered: Mutex::new(HashSet::new()),
            next_id: AtomicUsize::new(1),
            active: AtomicUsize::new(0),
            fence: AtomicBool::new(false),
            completed: AtomicUsize::new(0),
        })
    }

    /// Register a new task.
    ///
    /// Returns a `TaskHandle`; the task is tracked until the handle is dropped.
    pub fn register(self: &Arc<Self>) -> TaskHandle {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) as u64;
        self.registered.lock().unwrap().insert(id);
        self.active.fetch_add(1, Ordering::SeqCst);
        TaskHandle {
            id,
            supervisor: self.clone(),
        }
    }

    /// Returns `true` if the shutdown fence has been raised.
    pub fn is_fenced(&self) -> bool {
        self.fence.load(Ordering::SeqCst)
    }

    /// Raise the shutdown fence — stop accepting new work.
    pub fn fence(&self) {
        self.fence.store(true, Ordering::SeqCst);
    }

    /// Wait for all active tasks to complete (up to `timeout_ms`).
    ///
    /// Returns `Ok(())` when `active_count()` reaches zero, or
    /// `Err(DaemonError::Bootstrap(...))` if the timeout is exceeded.
    pub async fn drain(&self, timeout_ms: u64) -> Result<(), DaemonError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        while self.active.load(Ordering::SeqCst) > 0 {
            if std::time::Instant::now() > deadline {
                return Err(DaemonError::Bootstrap("shutdown drain timeout".into()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// Current number of active (registered but not yet completed) tasks.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Total number of tasks that have completed (dropped their handle).
    pub fn total_completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }
}

/// Graceful shutdown sequence (ADR-0018).
///
/// 1. Raise the fence to stop admitting new work.
/// 2. Drain all active tasks (up to `timeout_ms`).
/// 3. Log completion and return.
pub async fn graceful_shutdown(
    supervisor: &Arc<RuntimeTaskSupervisor>,
    timeout_ms: u64,
) -> Result<(), DaemonError> {
    tracing::info!("shutdown: fencing admission");
    supervisor.fence();

    tracing::info!(
        "shutdown: draining {} active tasks (timeout {}ms)",
        supervisor.active_count(),
        timeout_ms
    );
    supervisor.drain(timeout_ms).await?;

    let completed = supervisor.total_completed();
    tracing::info!(
        "shutdown: {} tasks completed, committing quiesced",
        completed
    );

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: create a tokio runtime for async tests ──────────────
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    // ── 1. register_increments_active ──────────────────────────────
    #[test]
    fn register_increments_active() {
        let s = RuntimeTaskSupervisor::new();
        assert_eq!(s.active_count(), 0);
        let _h = s.register();
        assert_eq!(s.active_count(), 1);
    }

    // ── 2. drop_handle_decrements_active ───────────────────────────
    #[test]
    fn drop_handle_decrements_active() {
        let s = RuntimeTaskSupervisor::new();
        let h = s.register();
        assert_eq!(s.active_count(), 1);
        drop(h);
        assert_eq!(s.active_count(), 0);
        assert_eq!(s.total_completed(), 1);
    }

    // ── 3. fence_prevents_new_work_check ───────────────────────────
    #[test]
    fn fence_prevents_new_work_check() {
        let s = RuntimeTaskSupervisor::new();
        assert!(!s.is_fenced());
        s.fence();
        assert!(s.is_fenced());
    }

    // ── 4. drain_waits_for_completion ──────────────────────────────
    #[test]
    fn drain_waits_for_completion() {
        let s = RuntimeTaskSupervisor::new();
        let h = s.register();
        drop(h); // complete immediately
        let rt = rt();
        rt.block_on(async {
            s.drain(5000).await.unwrap();
        });
        assert_eq!(s.active_count(), 0);
    }

    // ── 5. drain_timeout_returns_error ─────────────────────────────
    #[test]
    fn drain_timeout_returns_error() {
        let s = RuntimeTaskSupervisor::new();
        let _h = s.register(); // never dropped — active stays 1
        let rt = rt();
        let result = rt.block_on(async { s.drain(50).await });
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("drain timeout") || msg.contains("bootstrap error"),
            "expected drain timeout, got: {msg}"
        );
    }

    // ── 6. graceful_shutdown_fences_and_drains ─────────────────────
    #[test]
    fn graceful_shutdown_fences_and_drains() {
        let s = RuntimeTaskSupervisor::new();
        let h = s.register();
        drop(h);
        let rt = rt();
        rt.block_on(async {
            graceful_shutdown(&s, 5000).await.unwrap();
        });
        assert!(s.is_fenced());
        assert_eq!(s.active_count(), 0);
    }

    // ── 7. multiple_register_concurrent ────────────────────────────
    #[test]
    fn multiple_register_concurrent() {
        let s = RuntimeTaskSupervisor::new();
        let handles: Vec<_> = (0..10).map(|_| s.register()).collect();
        assert_eq!(s.active_count(), 10);
        drop(handles);
        let rt = rt();
        rt.block_on(async {
            s.drain(5000).await.unwrap();
        });
        assert_eq!(s.active_count(), 0);
        assert_eq!(s.total_completed(), 10);
    }

    // ── 8. forced_shutdown_skips_drain ─────────────────────────────
    #[test]
    fn forced_shutdown_skips_drain() {
        let s = RuntimeTaskSupervisor::new();
        let _h = s.register(); // held open
        // Fence without draining — forced shutdown
        s.fence();
        assert!(s.is_fenced());
        assert_eq!(s.active_count(), 1); // still active, not drained
    }
}
