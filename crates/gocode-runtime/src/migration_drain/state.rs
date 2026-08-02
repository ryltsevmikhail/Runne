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
