//! Platform supervision tests: generation allocation, restart budget,
//! bounded evidence wait.

use runne_engine_platform::{LocalHostSupervisor, LocalProcessLimitEnvelope, SupervisorConfig};

fn config(executable: &std::path::Path) -> SupervisorConfig {
    SupervisorConfig {
        executable: executable.to_path_buf(),
        limits: LocalProcessLimitEnvelope {
            address_space_bytes: 1 << 30,
            resident_bytes: 1 << 28,
            active_time_ms: 60_000,
            descriptor_count: 64,
            process_count: 1,
        },
        restart_budget: 2,
        budget_window: std::time::Duration::from_secs(60),
    }
}

#[test]
fn executable_missing_is_rejected() {
    let dir = tempfile::tempdir().expect("dir");
    let missing = dir.path().join("no-such-host");
    let err = LocalHostSupervisor::new(config(&missing)).expect_err("missing");
    assert!(matches!(
        err,
        runne_engine_platform::SupervisorError::ExecutableMissing
    ));
}

#[test]
fn generation_allocation_is_monotonic() {
    let dir = tempfile::tempdir().expect("dir");
    let host_bin = dir.path().join("host");
    std::fs::write(&host_bin, b"x").expect("write");
    let mut supervisor = LocalHostSupervisor::new(config(&host_bin)).expect("supervisor");
    let a = supervisor.allocate_generation().expect("gen a");
    let b = supervisor.allocate_generation().expect("gen b");
    assert!(b.0 > a.0);
}

#[test]
fn restart_budget_is_enforced() {
    let dir = tempfile::tempdir().expect("dir");
    let host_bin = dir.path().join("host");
    std::fs::write(&host_bin, b"x").expect("write");
    let mut supervisor = LocalHostSupervisor::new(config(&host_bin)).expect("supervisor");
    supervisor.allocate_generation().expect("gen 1");
    supervisor.allocate_generation().expect("gen 2");
    let err = supervisor.allocate_generation().expect_err("budget");
    assert!(matches!(
        err,
        runne_engine_platform::SupervisorError::RestartBudgetExhausted
    ));
}
