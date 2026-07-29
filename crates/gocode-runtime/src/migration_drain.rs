//! Cohort-scoped migration admission and drain control.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use gocode_application::migration::types::{ArtifactDigest, CohortSelector, RoutingGeneration};
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

impl MigrationDrainController {
    /// Register one exact cohort and routing generation.
    pub fn register_cohort(
        &self,
        cohort: CohortSelector,
        routing_generation: RoutingGeneration,
    ) -> Result<(), RuntimeMigrationError> {
        let digest = cohort_digest(&cohort);
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        if let Some(existing) = state.cohorts.get(&digest) {
            if existing.cohort != cohort {
                return Err(RuntimeMigrationError::CohortDigestCollision);
            }
            if existing.routing_generation != routing_generation {
                return Err(RuntimeMigrationError::RoutingGenerationMismatch {
                    expected: existing.routing_generation,
                    actual: routing_generation,
                });
            }
            return Ok(());
        }
        state.cohorts.insert(
            digest,
            CohortState {
                cohort,
                routing_generation,
                admission: CohortAdmissionState::Accepting,
                work: BTreeMap::new(),
                source_high_water: 0,
            },
        );
        Ok(())
    }

    /// Admit one work item when the exact cohort generation is accepting.
    pub fn try_admit(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        binding_id: MigrationWorkId,
    ) -> Result<MigrationWorkLease, RuntimeMigrationError> {
        let digest = cohort_digest(cohort);
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort_state = exact_cohort_mut(&mut state, digest, cohort)?;
        validate_generation(cohort_state, routing_generation)?;
        if cohort_state.admission != CohortAdmissionState::Accepting {
            return Err(RuntimeMigrationError::AdmissionClosed);
        }
        if cohort_state.work.contains_key(&binding_id) {
            return Err(RuntimeMigrationError::DuplicateWorkId);
        }
        cohort_state.source_high_water = cohort_state
            .source_high_water
            .checked_add(1)
            .ok_or(RuntimeMigrationError::HighWaterExhausted)?;
        cohort_state
            .work
            .insert(binding_id.clone(), WorkDisposition::Running);
        Ok(MigrationWorkLease {
            binding_id,
            cohort_digest: digest,
            routing_generation,
            inner: Arc::downgrade(&self.inner),
            settled: false,
        })
    }

    /// Close new admission for one exact cohort generation.
    pub fn close_admission(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
    ) -> Result<(), RuntimeMigrationError> {
        let digest = cohort_digest(cohort);
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort_state = exact_cohort_mut(&mut state, digest, cohort)?;
        validate_generation(cohort_state, routing_generation)?;
        if cohort_state.admission == CohortAdmissionState::Accepting {
            cohort_state.admission = CohortAdmissionState::Draining;
        }
        Ok(())
    }

    /// Close admission and wait for a complete or timed-out exact report.
    pub async fn drain(&self, request: DrainRequest) -> Result<DrainReport, RuntimeMigrationError> {
        if request.timeout.is_zero() {
            return Err(RuntimeMigrationError::InvalidTimeout);
        }
        self.close_admission(&request.cohort, request.routing_generation)?;
        let digest = cohort_digest(&request.cohort);
        let deadline = Instant::now() + request.timeout;

        loop {
            let notified = self.inner.changed.notified();
            let report = self.report_for(
                digest,
                &request.cohort,
                request.routing_generation,
                DrainDisposition::Complete,
            )?;
            if report.is_complete() {
                self.mark_closed(digest, &request.cohort, request.routing_generation)?;
                return Ok(report);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
                return self.report_for(
                    digest,
                    &request.cohort,
                    request.routing_generation,
                    DrainDisposition::TimedOut,
                );
            }
        }
    }

    /// Mark accepted work as requiring deterministic recovery.
    pub fn mark_recovery_required(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        binding_id: &MigrationWorkId,
    ) -> Result<(), RuntimeMigrationError> {
        self.mark_work(
            cohort,
            routing_generation,
            binding_id,
            WorkDisposition::RecoveryRequired,
        )
    }

    /// Mark accepted work as having an uncertain external-effect disposition.
    pub fn mark_uncertain(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        binding_id: &MigrationWorkId,
    ) -> Result<(), RuntimeMigrationError> {
        self.mark_work(
            cohort,
            routing_generation,
            binding_id,
            WorkDisposition::Uncertain,
        )
    }

    /// Mark accepted work as owned by a stale worker generation.
    pub fn mark_stale_worker(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        binding_id: &MigrationWorkId,
    ) -> Result<(), RuntimeMigrationError> {
        self.mark_work(
            cohort,
            routing_generation,
            binding_id,
            WorkDisposition::StaleWorker,
        )
    }

    fn mark_work(
        &self,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        binding_id: &MigrationWorkId,
        disposition: WorkDisposition,
    ) -> Result<(), RuntimeMigrationError> {
        let digest = cohort_digest(cohort);
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort_state = exact_cohort_mut(&mut state, digest, cohort)?;
        validate_generation(cohort_state, routing_generation)?;
        let work = cohort_state
            .work
            .get_mut(binding_id)
            .ok_or(RuntimeMigrationError::WorkNotFound)?;
        *work = disposition;
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(())
    }

    fn report_for(
        &self,
        digest: ArtifactDigest,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
        disposition: DrainDisposition,
    ) -> Result<DrainReport, RuntimeMigrationError> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort_state = exact_cohort(&state, digest, cohort)?;
        validate_generation(cohort_state, routing_generation)?;
        let mut report = DrainReport {
            disposition,
            completed: Vec::new(),
            still_running: Vec::new(),
            recovery_required: Vec::new(),
            uncertain: Vec::new(),
            stale_workers: Vec::new(),
            source_high_water: cohort_state.source_high_water,
        };
        for (binding_id, work) in &cohort_state.work {
            match work {
                WorkDisposition::Running => report.still_running.push(binding_id.clone()),
                WorkDisposition::Completed => report.completed.push(binding_id.clone()),
                WorkDisposition::RecoveryRequired => {
                    report.recovery_required.push(binding_id.clone());
                }
                WorkDisposition::Uncertain => report.uncertain.push(binding_id.clone()),
                WorkDisposition::StaleWorker => report.stale_workers.push(binding_id.clone()),
            }
        }
        Ok(report)
    }

    fn mark_closed(
        &self,
        digest: ArtifactDigest,
        cohort: &CohortSelector,
        routing_generation: RoutingGeneration,
    ) -> Result<(), RuntimeMigrationError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort_state = exact_cohort_mut(&mut state, digest, cohort)?;
        validate_generation(cohort_state, routing_generation)?;
        cohort_state.admission = CohortAdmissionState::Closed;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct DrainInner {
    state: Mutex<DrainState>,
    changed: Notify,
}

#[derive(Debug, Default)]
struct DrainState {
    cohorts: BTreeMap<ArtifactDigest, CohortState>,
}

#[derive(Debug)]
struct CohortState {
    cohort: CohortSelector,
    routing_generation: RoutingGeneration,
    admission: CohortAdmissionState,
    work: BTreeMap<MigrationWorkId, WorkDisposition>,
    source_high_water: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkDisposition {
    Running,
    Completed,
    RecoveryRequired,
    Uncertain,
    StaleWorker,
}

/// Lease proving one work item was admitted before cohort closure.
pub struct MigrationWorkLease {
    binding_id: MigrationWorkId,
    cohort_digest: ArtifactDigest,
    routing_generation: RoutingGeneration,
    inner: Weak<DrainInner>,
    settled: bool,
}

impl MigrationWorkLease {
    /// Return the accepted binding identity.
    pub fn binding_id(&self) -> &MigrationWorkId {
        &self.binding_id
    }

    /// Mark the admitted work item complete.
    pub fn complete(mut self) -> Result<(), RuntimeMigrationError> {
        let inner = self
            .inner
            .upgrade()
            .ok_or(RuntimeMigrationError::Unavailable)?;
        let mut state = inner
            .state
            .lock()
            .map_err(|_| RuntimeMigrationError::Unavailable)?;
        let cohort = state
            .cohorts
            .get_mut(&self.cohort_digest)
            .ok_or(RuntimeMigrationError::CohortNotRegistered)?;
        validate_generation(cohort, self.routing_generation)?;
        let work = cohort
            .work
            .get_mut(&self.binding_id)
            .ok_or(RuntimeMigrationError::WorkNotFound)?;
        *work = WorkDisposition::Completed;
        self.settled = true;
        drop(state);
        inner.changed.notify_waiters();
        Ok(())
    }
}

impl fmt::Debug for MigrationWorkLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationWorkLease")
            .field("binding_id", &self.binding_id)
            .field("routing_generation", &self.routing_generation)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl PartialEq for MigrationWorkLease {
    fn eq(&self, other: &Self) -> bool {
        self.binding_id == other.binding_id
            && self.cohort_digest == other.cohort_digest
            && self.routing_generation == other.routing_generation
    }
}

impl Eq for MigrationWorkLease {}

impl Drop for MigrationWorkLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let Ok(mut state) = inner.state.lock() else {
            return;
        };
        let Some(cohort) = state.cohorts.get_mut(&self.cohort_digest) else {
            return;
        };
        let Some(work) = cohort.work.get_mut(&self.binding_id) else {
            return;
        };
        if *work == WorkDisposition::Running {
            *work = WorkDisposition::Uncertain;
            drop(state);
            inner.changed.notify_waiters();
        }
    }
}

fn exact_cohort<'a>(
    state: &'a DrainState,
    digest: ArtifactDigest,
    cohort: &CohortSelector,
) -> Result<&'a CohortState, RuntimeMigrationError> {
    let found = state
        .cohorts
        .get(&digest)
        .ok_or(RuntimeMigrationError::CohortNotRegistered)?;
    if found.cohort != *cohort {
        return Err(RuntimeMigrationError::CohortDigestCollision);
    }
    Ok(found)
}

fn exact_cohort_mut<'a>(
    state: &'a mut DrainState,
    digest: ArtifactDigest,
    cohort: &CohortSelector,
) -> Result<&'a mut CohortState, RuntimeMigrationError> {
    let found = state
        .cohorts
        .get_mut(&digest)
        .ok_or(RuntimeMigrationError::CohortNotRegistered)?;
    if found.cohort != *cohort {
        return Err(RuntimeMigrationError::CohortDigestCollision);
    }
    Ok(found)
}

fn validate_generation(
    state: &CohortState,
    attempted: RoutingGeneration,
) -> Result<(), RuntimeMigrationError> {
    if state.routing_generation == attempted {
        Ok(())
    } else {
        Err(RuntimeMigrationError::RoutingGenerationMismatch {
            expected: state.routing_generation,
            actual: attempted,
        })
    }
}

fn cohort_digest(cohort: &CohortSelector) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-migration-drain-cohort\x01");
    hasher.update((cohort.dimensions().len() as u16).to_be_bytes());
    for dimension in cohort.dimensions() {
        hasher.update((dimension.key().len() as u16).to_be_bytes());
        hasher.update(dimension.key().as_bytes());
        hasher.update((dimension.value().len() as u16).to_be_bytes());
        hasher.update(dimension.value().as_bytes());
    }
    ArtifactDigest::from_bytes(hasher.finalize().into())
}
