//! Host supervision: launch budget, readiness gates and bounded
//! dual-owner cleanup. Platform backend is pluggable: the default
//! backend runs the deterministic fake host in-process (no child
//! process), because real process spawn requires the signed containment
//! helper qualification (Phase 6B) which is not available yet.

use crate::local_process::{
    HostGeneration, LocalProcessLimitEnvelope, ProcessEvidence, WorkerGeneration,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorError {
    ExecutableMissing,
    RestartBudgetExhausted,
    SpawnFailed,
    DeadlineExceeded,
    AlreadyStopped,
    /// The host generation already occupies its single worker slot.
    WorkerSlotOccupied,
}

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Absolute path to the declared host executable. Recorded for the
    /// future signed-helper qualification; unused by the in-process
    /// backend.
    pub executable: PathBuf,
    pub limits: LocalProcessLimitEnvelope,
    /// Maximum host restarts within the budget window.
    pub restart_budget: u32,
    /// Restart budget window.
    pub budget_window: Duration,
}

/// Lifecycle tracker: restart budget + generation allocation. The
/// supervisor owns BOTH role generations: every host generation has
/// exactly one declared worker slot, and daemon-loss cleanup order is
/// deterministically worker-before-host (release the worker slot first).
#[derive(Debug)]
pub struct LocalHostSupervisor {
    config: SupervisorConfig,
    restarts: Vec<Instant>,
    next_generation: u64,
    next_worker_generation: u64,
    worker_slots: BTreeMap<u64, WorkerGeneration>,
}

impl LocalHostSupervisor {
    pub fn new(config: SupervisorConfig) -> Result<Self, SupervisorError> {
        if !config.executable.as_os_str().is_empty() && !config.executable.is_file() {
            return Err(SupervisorError::ExecutableMissing);
        }
        Ok(Self {
            config,
            restarts: Vec::new(),
            next_generation: 1,
            next_worker_generation: 1,
            worker_slots: BTreeMap::new(),
        })
    }

    fn consume_budget(&mut self) -> Result<(), SupervisorError> {
        let now = Instant::now();
        self.restarts
            .retain(|t| now.duration_since(*t) < self.config.budget_window);
        if self.restarts.len() as u32 >= self.config.restart_budget {
            return Err(SupervisorError::RestartBudgetExhausted);
        }
        self.restarts.push(now);
        Ok(())
    }

    /// Allocates the next host generation if the restart budget allows
    /// it. Budget: max `restart_budget` launches per `budget_window`
    /// across BOTH roles.
    pub fn allocate_generation(&mut self) -> Result<HostGeneration, SupervisorError> {
        self.consume_budget()?;
        let generation = HostGeneration(self.next_generation);
        self.next_generation += 1;
        Ok(generation)
    }

    /// Occupies the single worker slot of `host` with a fresh worker
    /// generation (same restart budget as host launches).
    pub fn allocate_worker_generation(
        &mut self,
        host: HostGeneration,
    ) -> Result<WorkerGeneration, SupervisorError> {
        if self.worker_slots.contains_key(&host.0) {
            return Err(SupervisorError::WorkerSlotOccupied);
        }
        self.consume_budget()?;
        let generation = WorkerGeneration(self.next_worker_generation);
        self.next_worker_generation += 1;
        self.worker_slots.insert(host.0, generation);
        Ok(generation)
    }

    /// Releases the worker slot (worker-before-host cleanup).
    pub fn release_worker_slot(&mut self, host: HostGeneration) -> Result<(), SupervisorError> {
        self.worker_slots
            .remove(&host.0)
            .map(|_| ())
            .ok_or(SupervisorError::AlreadyStopped)
    }

    pub fn worker_slot(&self, host: HostGeneration) -> Option<WorkerGeneration> {
        self.worker_slots.get(&host.0).copied()
    }
}

/// Bounded evidence wait helper over a closure that polls terminal
/// state. Returns DeadlineExceeded when the wait exceeds the deadline.
pub fn wait_for<F: FnMut() -> Option<ProcessEvidence>>(
    mut poll: F,
    deadline: Duration,
) -> Result<ProcessEvidence, SupervisorError> {
    let started = Instant::now();
    loop {
        if let Some(evidence) = poll() {
            return Ok(evidence);
        }
        if started.elapsed() > deadline {
            return Err(SupervisorError::DeadlineExceeded);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_process::LocalProcessLimitEnvelope;

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            executable: PathBuf::new(),
            limits: LocalProcessLimitEnvelope {
                address_space_bytes: u64::MAX,
                resident_bytes: u64::MAX,
                active_time_ms: u64::MAX,
                descriptor_count: u16::MAX as u32,
                process_count: 2,
            },
            restart_budget: 2,
            budget_window: Duration::from_secs(60),
        }
    }

    #[test]
    fn worker_slot_is_one_per_host_generation() {
        // Slot semantics are independent of the shared restart budget:
        // raise the budget so only slot rules are exercised.
        let mut cfg = config();
        cfg.restart_budget = 3;
        let mut sup = LocalHostSupervisor::new(cfg).expect("sup");
        let host = sup.allocate_generation().expect("host gen");
        let w1 = sup.allocate_worker_generation(host).expect("slot 1");
        assert_eq!(sup.worker_slot(host), Some(w1));
        // Distinct identity LINES: values may coincide, types may not.
        let _: WorkerGeneration = w1;
        assert_eq!(
            sup.allocate_worker_generation(host).expect_err("occupied"),
            SupervisorError::WorkerSlotOccupied
        );
        sup.release_worker_slot(host).expect("release");
        assert_eq!(
            sup.release_worker_slot(host).expect_err("already"),
            SupervisorError::AlreadyStopped
        );
        let w2 = sup.allocate_worker_generation(host).expect("slot 2");
        assert_ne!(w1, w2);
    }

    #[test]
    fn both_roles_share_the_restart_budget() {
        let mut sup = LocalHostSupervisor::new(config()).expect("sup");
        let h1 = sup.allocate_generation().expect("host 1 (1/2)");
        let _ = sup.allocate_worker_generation(h1).expect("worker (2/2)");
        let h2 = sup
            .allocate_generation()
            .expect_err("budget exhausted at 2/2");
        assert!(matches!(h2, SupervisorError::RestartBudgetExhausted));
    }

    #[test]
    fn cleanup_releases_worker_slot_first() {
        // Daemon-loss cleanup order: worker-before-host. The host
        // generation stays allocator-owned; only the slot releases.
        let mut cfg = config();
        cfg.restart_budget = 3;
        let mut sup = LocalHostSupervisor::new(cfg).expect("sup");
        let host = sup.allocate_generation().expect("host");
        let worker = sup.allocate_worker_generation(host).expect("worker");
        sup.release_worker_slot(host).expect("worker first");
        assert_eq!(sup.worker_slot(host), None);
        let new_worker = sup.allocate_worker_generation(host).expect("respawn");
        assert_ne!(worker, new_worker);
    }
}
