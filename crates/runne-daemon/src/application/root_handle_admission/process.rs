impl RootAdmissionGateway {
    /// Acquires the durable trust effect fence before a canonical writer
    /// transaction. The caller must keep it through gated release.
    pub(crate) fn acquire_local_command_effect_lease(
        &self,
        workspace_id: WorkspaceId,
        expected: runne_application::project_trust::TrustToken,
    ) -> Result<
        Box<dyn runne_application::project_trust::ProjectTrustEffectLease>,
        RootHandleBrokerError,
    > {
        let Some(authority) = &self.0 else {
            return Err(RootHandleBrokerError::Unavailable);
        };
        authority
            .acquire_workspace_local_command_effect_lease(workspace_id, expected)
            .map_err(|error| match error {
                TrustSourceError::Unavailable => RootHandleBrokerError::Unavailable,
                _ => RootHandleBrokerError::Rejected,
            })
    }

    /// Captures local-command trust and the current verified root before any
    /// approval is created. The callback must return handles/identities, not
    /// an unchecked root path.
    pub(crate) fn with_local_command_root<T>(
        &self,
        workspace_id: WorkspaceId,
        operation: impl FnOnce(
            &VerifiedRootHandle,
            u64,
            [u8; 16],
            u64,
            [u8; 32],
            runne_application::project_trust::LocalCommandAdmission,
        ) -> Result<T, RootHandleBrokerError>,
    ) -> Result<T, RootHandleBrokerError> {
        let Some(authority) = &self.0 else {
            return Err(RootHandleBrokerError::Unavailable);
        };
        let admission = authority
            .admit_workspace_local_command(workspace_id)
            .map_err(|error| match error {
                TrustSourceError::Unavailable => RootHandleBrokerError::Unavailable,
                _ => RootHandleBrokerError::Rejected,
            })?;
        authority
            .store
            .with_current_workspace_binding(PRINCIPAL, workspace_id, |version, project_id| {
                let state = authority
                    .state
                    .lock()
                    .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)?;
                if state.stopped {
                    return Err(ProjectWorkspaceRepositoryError::Unavailable);
                }
                let active = state
                    .active
                    .get(&workspace_id)
                    .filter(|active| active_root_is_current(version, active.version))
                    .ok_or(ProjectWorkspaceRepositoryError::Unavailable)?;
                operation(
                    &active.handle,
                    version,
                    project_id,
                    active.version,
                    active.handle.filesystem_identity_digest(),
                    admission,
                )
                .map_err(|error| match error {
                    RootHandleBrokerError::Rejected => ProjectWorkspaceRepositoryError::NotFound,
                    RootHandleBrokerError::Unavailable => {
                        ProjectWorkspaceRepositoryError::Unavailable
                    }
                })
            })
            .map_err(map_root_workspace_error)
    }

    /// Revalidates the in-memory root binding while the caller owns the
    /// canonical immediate writer transaction and trust effect lease. It does
    /// not acquire the store writer recursively.
    pub(crate) fn with_local_command_root_version<T>(
        &self,
        workspace_id: WorkspaceId,
        expected_workspace_version: u64,
        expected_root_version: u64,
        expected_root_identity: [u8; 32],
        operation: impl FnOnce(&VerifiedRootHandle) -> Result<T, RootHandleBrokerError>,
    ) -> Result<T, RootHandleBrokerError> {
        let Some(authority) = &self.0 else {
            return Err(RootHandleBrokerError::Unavailable);
        };
        let state = authority
            .state
            .lock()
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        if state.stopped {
            return Err(RootHandleBrokerError::Unavailable);
        }
        let active = state
            .active
            .get(&workspace_id)
            .filter(|active| active.version == expected_root_version)
            .filter(|active| active.handle.filesystem_identity_digest() == expected_root_identity)
            .filter(|active| active_root_is_current(expected_workspace_version, active.version))
            .ok_or(RootHandleBrokerError::Rejected)?;
        operation(&active.handle)
    }

    /// Runs one native process preparation only against the current admitted root.
    ///
    /// The callback receives a borrowed verified handle and cannot retain a path
    /// or bypass the workspace-version fence.
    pub(crate) fn with_process_root<T>(
        &self,
        workspace_id: WorkspaceId,
        operation: impl FnOnce(&VerifiedRootHandle) -> Result<T, RootHandleBrokerError>,
    ) -> Result<T, RootHandleBrokerError> {
        let Some(authority) = &self.0 else {
            return Err(RootHandleBrokerError::Unavailable);
        };
        // Stage-1 admission precedes any root access on the helper-process
        // channel too (inventory §A): the channel is activation-gated, so the
        // gate denies the launch structurally instead of relying on the
        // absence of a grant path.
        self.admit_workspace_source(workspace_id, SourceChannel::Helpers, None)
            .map_err(|error| match error {
                TrustSourceError::Unavailable => RootHandleBrokerError::Unavailable,
                _ => RootHandleBrokerError::Rejected,
            })?;
        authority
            .store
            .with_current_workspace_version(PRINCIPAL, workspace_id, |version| {
                let state = authority
                    .state
                    .lock()
                    .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)?;
                let active = state
                    .active
                    .get(&workspace_id)
                    .filter(|active| active_root_is_current(version, active.version))
                    .ok_or(ProjectWorkspaceRepositoryError::Unavailable)?;
                operation(&active.handle).map_err(|error| match error {
                    RootHandleBrokerError::Rejected => ProjectWorkspaceRepositoryError::NotFound,
                    RootHandleBrokerError::Unavailable => {
                        ProjectWorkspaceRepositoryError::Unavailable
                    }
                })
            })
            .map_err(|error| match error {
                ProjectWorkspaceRepositoryError::NotFound
                | ProjectWorkspaceRepositoryError::Conflict
                | ProjectWorkspaceRepositoryError::Forbidden
                | ProjectWorkspaceRepositoryError::InvariantViolation => {
                    RootHandleBrokerError::Rejected
                }
                ProjectWorkspaceRepositoryError::Unavailable => RootHandleBrokerError::Unavailable,
            })
    }
}

fn map_root_workspace_error(error: ProjectWorkspaceRepositoryError) -> RootHandleBrokerError {
    match error {
        ProjectWorkspaceRepositoryError::NotFound
        | ProjectWorkspaceRepositoryError::Conflict
        | ProjectWorkspaceRepositoryError::Forbidden
        | ProjectWorkspaceRepositoryError::InvariantViolation => RootHandleBrokerError::Rejected,
        ProjectWorkspaceRepositoryError::Unavailable => RootHandleBrokerError::Unavailable,
    }
}
