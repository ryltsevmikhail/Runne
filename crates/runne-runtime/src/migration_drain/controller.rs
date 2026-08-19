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
