pub(crate) enum TrustRootDecisionError<E> {
    Unavailable,
    Stale,
    Operation(E),
}

impl RootAdmissionGateway {
    pub(crate) fn read_current_trust_root_version(
        &self,
        workspace: runne_domain::id::WorkspaceId,
        workspace_version: u64,
    ) -> Result<Option<u64>, ()> {
        let Some(authority) = &self.0 else { return Ok(None); };
        let state = authority.state.lock().map_err(|_| ())?;
        if state.stopped { return Ok(None); }
        Ok(state.active.get(&workspace)
            .filter(|active| active_root_is_current(workspace_version, active.version))
            .map(|active| active.version))
    }

    /// Runs the decision while the retained-root binding is frozen under its
    /// mutex and canonical workspace metadata is locked. No root identity or
    /// filesystem content escapes this callback.
    pub(crate) fn with_current_trust_root<T, E>(
        &self,
        workspace: runne_domain::id::WorkspaceId,
        workspace_version: u64,
        expected: u64,
        operation: impl FnOnce(u64) -> Result<T, E>,
    ) -> Result<T, TrustRootDecisionError<E>> {
        let Some(authority) = &self.0 else {
            return Err(TrustRootDecisionError::Unavailable);
        };
        let state = authority.state.lock().map_err(|_| TrustRootDecisionError::Unavailable)?;
        let active = state
            .active
            .get(&workspace)
            .filter(|active| active_root_is_current(workspace_version, active.version))
            .ok_or(TrustRootDecisionError::Unavailable)?;
        if state.stopped {
            return Err(TrustRootDecisionError::Unavailable);
        }
        if active.version != expected { return Err(TrustRootDecisionError::Stale); }
        operation(active.version).map_err(TrustRootDecisionError::Operation)
    }
}
