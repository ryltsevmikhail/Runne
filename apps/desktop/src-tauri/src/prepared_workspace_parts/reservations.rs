impl PreparedWorkspaceManager {
    pub(crate) fn reserve_guard(
        &self,
        binding: PreparedWorkspaceBinding,
        now: Instant,
    ) -> Result<PreparedWorkspaceReservationGuard, SelectionError> {
        self.reserve(binding, now)
            .map(|reference| PreparedWorkspaceReservationGuard {
                manager: self.clone(),
                reference: Some(reference),
            })
    }

    /// Reserves an exact binding before the protected process accepts a root.
    pub fn reserve(
        &self,
        binding: PreparedWorkspaceBinding,
        now: Instant,
    ) -> Result<PreparedWorkspaceRef, SelectionError> {
        let ttl = state_prepared_ttl(&self.state)?;
        let expires_at = now.checked_add(ttl).ok_or(SelectionError)?;
        let mut state = self.state.lock().map_err(|_| SelectionError)?;
        state.prepared.retain(|_, entry| {
            if entry.expires_at > now { return true; }
            match entry.phase {
                PreparedWorkspacePhase::Attempting { attempt_id, .. } => {
                    entry.phase = PreparedWorkspacePhase::Attempting { attempt_id, revoked: true };
                    true
                }
                PreparedWorkspacePhase::Ready | PreparedWorkspacePhase::Retained
                | PreparedWorkspacePhase::Orphaned | PreparedWorkspacePhase::Opened => false,
            }
        });
        state.reservations.retain(|_, entry| entry.expires_at > now);
        if state.prepared.len() + state.reservations.len()
            >= crate::directory_selection::MAX_SELECTIONS
            || state
                .existing_generation(&binding.window)
                .map_err(|_| SelectionError)?
                != binding.generation
        {
            return Err(SelectionError);
        }
        self.start_expiry_sweeper(&mut state)?;
        for _ in 0..4 {
            let reference = random_reference();
            if !state.prepared.contains_key(&reference)
                && let Entry::Vacant(slot) = state.reservations.entry(reference.clone())
            {
                slot.insert(PreparedWorkspaceReservation {
                    window: binding.window,
                    generation: binding.generation,
                    request: binding.request,
                    workspace_id: binding.workspace_id,
                    expected_version: binding.expected_version,
                    expires_at,
                });
                return Ok(PreparedWorkspaceRef(reference));
            }
        }
        Err(SelectionError)
    }

    /// Commits a daemon admission only while its prior reservation still holds.
    pub fn commit(
        &self,
        reference: &PreparedWorkspaceRef,
        root: VerifiedRootHandle,
        admission: ProtectedRootHandleAdmission,
        operation_permit: &mut Option<tokio::sync::OwnedMutexGuard<()>>,
        now: Instant,
    ) -> Result<(), SelectionError> {
        let mut state = self.state.lock().map_err(|_| SelectionError)?;
        let entry = state
            .reservations
            .remove(&reference.0)
            .ok_or(SelectionError)?;
        if entry.expires_at <= now
            || state
                .existing_generation(&entry.window)
                .map_err(|_| SelectionError)?
                != entry.generation
        {
            return Err(SelectionError);
        }
        state.prepared.insert(
            reference.0.clone(),
            PreparedWorkspaceEntry {
                window: entry.window,
                generation: entry.generation,
                request: entry.request,
                root: Some(root),
                admission: Some(admission),
                workspace_id: entry.workspace_id,
                expected_version: entry.expected_version,
                expires_at: entry.expires_at,
                operation_permit: operation_permit.take(),
                prepared_open: None,
                phase: PreparedWorkspacePhase::Ready,
            },
        );
        drop(state);
        Ok(())
    }

    /// Drops a reservation before it has transferred native authority.
    pub fn cancel(&self, reference: &PreparedWorkspaceRef) {
        self.cancel_reference(&reference.0);
    }

    fn cancel_reference(&self, reference: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.reservations.remove(reference);
        }
    }
}

fn state_prepared_ttl(state: &SharedSelectionState) -> Result<std::time::Duration, SelectionError> {
    state
        .lock()
        .map(|state| state.prepared_ttl.min(MAX_PREPARED_TTL))
        .map_err(|_| SelectionError)
}
