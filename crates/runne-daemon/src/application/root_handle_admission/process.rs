impl RootAdmissionGateway {
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
                    .filter(|active| active.version == version)
                    .ok_or(ProjectWorkspaceRepositoryError::Unavailable)?;
                operation(&active.handle).map_err(|error| match error {
                    RootHandleBrokerError::Rejected => {
                        ProjectWorkspaceRepositoryError::NotFound
                    }
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
