//! Integration tests for the shutdown subsystem.
//!
//! Tests the public API of `runne_daemon::shutdown`:
//! register, fence, drain, graceful_shutdown, and edge cases.

use runne_daemon::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};

/// Create a single-threaded tokio runtime for async test support.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

// ── 1. register_increments_active ──────────────────────────────────────

#[test]
fn register_increments_active() {
    let s = RuntimeTaskSupervisor::new();
    assert_eq!(s.active_count(), 0);
    let _h = s.register();
    assert_eq!(s.active_count(), 1);
}

// ── 2. drop_handle_decrements_active ───────────────────────────────────

#[test]
fn drop_handle_decrements_active() {
    let s = RuntimeTaskSupervisor::new();
    let h = s.register();
    assert_eq!(s.active_count(), 1);
    drop(h);
    assert_eq!(s.active_count(), 0);
    assert_eq!(s.total_completed(), 1);
}

// ── 3. fence_prevents_new_work_check ───────────────────────────────────

#[test]
fn fence_prevents_new_work_check() {
    let s = RuntimeTaskSupervisor::new();
    assert!(!s.is_fenced());
    s.fence();
    assert!(s.is_fenced());
}

// ── 4. drain_waits_for_completion ──────────────────────────────────────

#[test]
fn drain_waits_for_completion() {
    let s = RuntimeTaskSupervisor::new();
    let h = s.register();
    drop(h);
    let rt = rt();
    rt.block_on(async {
        s.drain(5000).await.unwrap();
    });
    assert_eq!(s.active_count(), 0);
}

// ── 5. drain_timeout_returns_error ─────────────────────────────────────

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

// ── 6. graceful_shutdown_fences_and_drains ─────────────────────────────

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

// ── 7. multiple_register_concurrent ────────────────────────────────────

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

// ── 8. forced_shutdown_skips_drain ─────────────────────────────────────

#[test]
fn forced_shutdown_skips_drain() {
    let s = RuntimeTaskSupervisor::new();
    let _h = s.register(); // held open
    s.fence();
    assert!(s.is_fenced());
    assert_eq!(s.active_count(), 1); // still active, not drained
}

// ── 9. graceful_shutdown_timeout ───────────────────────────────────────

#[test]
fn graceful_shutdown_timeout_returns_error() {
    let s = RuntimeTaskSupervisor::new();
    let _h = s.register(); // held open — drain will time out
    let rt = rt();
    let result = rt.block_on(async { graceful_shutdown(&s, 50).await });
    assert!(result.is_err());
    assert!(s.is_fenced()); // fence was raised even on timeout
}

// ── 10. register_after_fence_still_works_but_checkable ─────────────────

#[test]
fn register_after_fence_still_works_but_checkable() {
    let s = RuntimeTaskSupervisor::new();
    s.fence();
    assert!(s.is_fenced());
    // Registration itself is not blocked — callers must check is_fenced()
    let h = s.register();
    assert_eq!(s.active_count(), 1);
    drop(h);
}
