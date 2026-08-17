use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);

// These state types remain crate-internal while sibling root modules access them.
#[allow(clippy::redundant_pub_crate)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PreparedWorkspaceRestoreOutcome {
    Retained,
    Released,
}

#[allow(clippy::redundant_pub_crate)]
pub(super) struct PreparedWorkspaceOpenAttempt {
    manager: PreparedWorkspaceManager,
    reference: String,
    window: String,
    generation: u64,
    workspace_id: WorkspaceId,
    expected_version: u64,
    expires_at: Instant,
    attempt_id: u64,
    root: Option<VerifiedRootHandle>,
    admission: Option<ProtectedRootHandleAdmission>,
    permit: Option<tokio::sync::OwnedMutexGuard<()>>,
    prepared: Option<gocode_app_core::PreparedWorkspaceOpen>,
    reaper: Option<std::sync::Arc<dyn crate::NativeRootAdmissionLifecycle>>,
}

impl PreparedWorkspaceManager {
    #[allow(clippy::too_many_arguments)] // Private state-machine boundary keeps the transition inputs explicit.
    fn begin_open(
        &self, reference: &PreparedWorkspaceRef, window: &str, expected_generation: u64,
        request: &str, now: Instant, required_phase: PreparedWorkspacePhase,
        reaper: std::sync::Arc<dyn crate::NativeRootAdmissionLifecycle>,
    ) -> Result<PreparedWorkspaceOpenAttempt, SelectionError> {
        if !valid_binding(window) || !valid_binding(request) { return Err(SelectionError); }
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = state.existing_generation(window).map_err(|_| SelectionError)?;
        let entry = state.prepared.get_mut(&reference.0).ok_or(SelectionError)?;
        if entry.expires_at <= now || generation != expected_generation || entry.window != window
            || entry.generation != generation || entry.request != request || entry.phase != required_phase {
            return Err(SelectionError);
        }
        let attempt_id = NEXT_ATTEMPT_ID.fetch_add(1, Ordering::AcqRel).checked_add(1).ok_or(SelectionError)?;
        entry.phase = PreparedWorkspacePhase::Attempting { attempt_id, revoked: false };
        Ok(PreparedWorkspaceOpenAttempt {
            manager: self.clone(), reference: reference.0.clone(), window: entry.window.clone(),
            generation: entry.generation, workspace_id: entry.workspace_id,
            expected_version: entry.expected_version, expires_at: entry.expires_at, attempt_id,
            root: entry.root.take(), admission: entry.admission.take(),
            permit: entry.operation_permit.take(), prepared: entry.prepared_open.take(),
            reaper: Some(reaper),
        })
    }
}

impl PreparedWorkspaceOpenAttempt {
    pub(super) async fn prepare(&mut self, core: &gocode_app_core::AppCore) -> Result<(), gocode_app_core::AppCoreError> {
        if self.prepared.is_none() {
            let admission = self.admission.take().ok_or(gocode_app_core::AppCoreError::InvalidMutation)?;
            self.prepared = Some(core.prepare_open_selected_workspace(self.workspace_id, self.expected_version, admission).await?);
        }
        Ok(())
    }

    pub(super) async fn dispatch(&mut self, core: &gocode_app_core::AppCore) -> Result<(), gocode_app_core::NativeMutationFailure> {
        core.dispatch_prepared_workspace_open(self.prepared.as_mut().ok_or_else(gocode_app_core::NativeMutationFailure::pre_dispatch)?).await.map(|_| ())
    }

    pub(super) fn possible_send(&self) -> bool {
        self.prepared.as_ref().is_some_and(gocode_app_core::AppCore::prepared_workspace_open_possible_send)
    }

    pub(super) async fn reap(mut self) {
        if let Some(permit) = self.permit.take() {
            self.reaper.take().expect("prepared open owns a root reaper")
                .reap_failed_root_admission(permit).await;
        }
    }

    pub(super) fn retain(&mut self) -> PreparedWorkspaceRestoreOutcome {
        self.restore(PreparedWorkspacePhase::Retained)
    }

    pub(super) fn opened(&mut self) {
        self.root.take(); self.admission.take(); self.permit.take(); self.prepared.take();
        let mut state = self.manager.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.prepared.get_mut(&self.reference)
            && matches!(entry.phase, PreparedWorkspacePhase::Attempting { attempt_id, .. } if attempt_id == self.attempt_id)
        {
            if self.expires_at <= Instant::now() {
                state.prepared.remove(&self.reference);
            } else {
                entry.phase = PreparedWorkspacePhase::Opened;
                if self.manager.start_expiry_sweeper(&mut state).is_err() {
                    state.prepared.remove(&self.reference);
                }
            }
        }
    }

    fn restore(&mut self, phase: PreparedWorkspacePhase) -> PreparedWorkspaceRestoreOutcome {
        let mut state = self.manager.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation_matches = state.existing_generation(&self.window).ok() == Some(self.generation);
        let Some(entry) = state.prepared.get_mut(&self.reference) else {
            return PreparedWorkspaceRestoreOutcome::Released;
        };
        let active = matches!(entry.phase, PreparedWorkspacePhase::Attempting { attempt_id, revoked: false } if attempt_id == self.attempt_id);
        if !active || !generation_matches || self.expires_at <= Instant::now() {
            entry.phase = PreparedWorkspacePhase::Orphaned;
            drop(state);
            self.root.take(); self.admission.take(); self.prepared.take(); self.permit.take(); self.reaper.take();
            return PreparedWorkspaceRestoreOutcome::Released;
        }
        entry.root = self.root.take(); entry.admission = self.admission.take();
        entry.operation_permit = self.permit.take(); entry.prepared_open = self.prepared.take(); entry.phase = phase;
        PreparedWorkspaceRestoreOutcome::Retained
    }
}

impl Drop for PreparedWorkspaceOpenAttempt {
    fn drop(&mut self) {
        if self.possible_send() {
            let _ = self.retain();
        } else if let Some(permit) = self.permit.take() {
            if let Some(reaper) = self.reaper.take() {
                tauri::async_runtime::spawn(async move {
                    reaper.reap_failed_root_admission(permit).await;
                });
            } else { unreachable!("prepared open always owns a root reaper"); }
        }
    }
}
