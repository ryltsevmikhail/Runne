//! Cohort-scoped migration admission and drain control.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use runne_application::migration::types::{ArtifactDigest, CohortSelector, RoutingGeneration};
use sha2::{Digest, Sha256};
use tokio::{sync::Notify, time::Instant};

/// Admission state for one exact migration cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CohortAdmissionState {
    /// New work may be accepted.
    Accepting,
    /// Admission is closed and accepted work is being drained.
    Draining,
    /// Drain completed and the cohort remains closed.
    Closed,
}

/// Validated identity for one accepted runtime binding or work item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MigrationWorkId(String);

impl MigrationWorkId {
    /// Validate a bounded work identity.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeMigrationError> {
        const MAX_WORK_ID_BYTES: usize = 128;
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_WORK_ID_BYTES
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(RuntimeMigrationError::InvalidWorkId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Request to close one cohort and await bounded drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainRequest {
    /// Exact cohort to drain.
    pub cohort: CohortSelector,
    /// Routing generation expected by the caller.
    pub routing_generation: RoutingGeneration,
    /// Maximum wait before returning a non-success report.
    pub timeout: Duration,
}

impl DrainRequest {
    /// Construct a drain request.
    pub fn new(
        cohort: CohortSelector,
        routing_generation: RoutingGeneration,
        timeout: Duration,
    ) -> Self {
        Self {
            cohort,
            routing_generation,
            timeout,
        }
    }
}

/// Terminal disposition of one drain attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainDisposition {
    /// Every captured item reached a resolved state.
    Complete,
    /// Deadline elapsed with work or uncertainty remaining.
    TimedOut,
}

/// Exact cohort-scoped drain inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReport {
    /// Drain terminal disposition.
    pub disposition: DrainDisposition,
    /// Work completed before the report was captured.
    pub completed: Vec<MigrationWorkId>,
    /// Work still actively running.
    pub still_running: Vec<MigrationWorkId>,
    /// Work requiring recovery before cutover.
    pub recovery_required: Vec<MigrationWorkId>,
    /// Work whose external-effect disposition is uncertain.
    pub uncertain: Vec<MigrationWorkId>,
    /// Work owned by a stale runtime generation.
    pub stale_workers: Vec<MigrationWorkId>,
    /// Highest admission position captured for the cohort.
    pub source_high_water: u64,
}

impl DrainReport {
    /// Return true only for a fully resolved successful drain.
    pub fn is_complete(&self) -> bool {
        self.disposition == DrainDisposition::Complete
            && self.still_running.is_empty()
            && self.recovery_required.is_empty()
            && self.uncertain.is_empty()
            && self.stale_workers.is_empty()
    }

    /// Validate this immutable report as cutover evidence.
    pub fn validate_cutover_eligibility(&self) -> Result<(), RuntimeMigrationError> {
        if !self.recovery_required.is_empty()
            || !self.uncertain.is_empty()
            || !self.stale_workers.is_empty()
        {
            return Err(RuntimeMigrationError::UnresolvedEffect);
        }
        if self.disposition == DrainDisposition::TimedOut {
            return Err(RuntimeMigrationError::DrainTimedOut);
        }
        if !self.still_running.is_empty() {
            return Err(RuntimeMigrationError::DrainIncomplete);
        }
        Ok(())
    }
}

/// Typed cohort admission and drain failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMigrationError {
    /// Cohort has not been registered.
    CohortNotRegistered,
    /// Cohort digest collided with a different selector.
    CohortDigestCollision,
    /// Routing generation differs from the registered generation.
    RoutingGenerationMismatch {
        /// Registered generation.
        expected: RoutingGeneration,
        /// Attempted generation.
        actual: RoutingGeneration,
    },
    /// Cohort admission is draining or closed.
    AdmissionClosed,
    /// Work identity is invalid.
    InvalidWorkId,
    /// Work identity already exists in this cohort.
    DuplicateWorkId,
    /// Work identity was not found.
    WorkNotFound,
    /// Drain timeout is zero.
    InvalidTimeout,
    /// Drain deadline elapsed before every running item completed.
    DrainTimedOut,
    /// A supposedly complete report still contains active work.
    DrainIncomplete,
    /// Recovery, uncertain-effect or stale-worker work remains unresolved.
    UnresolvedEffect,
    /// Admission high-water counter overflowed.
    HighWaterExhausted,
    /// Controller synchronization state is unavailable.
    Unavailable,
}

/// Cohort-scoped admission and drain authority.
#[derive(Debug, Clone, Default)]
pub struct MigrationDrainController {
    inner: Arc<DrainInner>,
}

include!("migration_drain/controller.rs");
include!("migration_drain/state.rs");
include!("migration_drain/helpers.rs");
