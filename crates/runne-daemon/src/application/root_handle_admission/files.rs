use runne_api::{
    WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileListRequest, WorkspaceFilePage,
    WorkspaceFileReadRequest, WorkspaceFileEntry, WorkspaceFileKind,
};
use runne_application::ports::WorkspaceFileProvider;
use runne_application::ports::ProjectWorkspaceRepositoryError;
use runne_domain::id::WorkspaceId;
use runne_platform_desktop::RootFileKind;

impl RootAdmissionGateway {
    fn with_workspace_root<T>(
        &self,
        workspace_id: WorkspaceId,
        operation: impl FnOnce(&VerifiedRootHandle) -> Result<T, WorkspaceFileHostError>,
    ) -> Result<T, WorkspaceFileHostError> {
        let Some(authority) = &self.0 else { return Err(WorkspaceFileHostError::Unavailable); };
        authority.store.with_current_workspace_version(
            PRINCIPAL,
            workspace_id,
            |workspace_version| {
                let state = authority
                    .state
                    .lock()
                    .map_err(|_| ProjectWorkspaceRepositoryError::Unavailable)?;
                let Some(active) = state.active.get(&workspace_id) else {
                    return Ok(Err(WorkspaceFileHostError::Unavailable));
                };
                if !active_root_is_current(workspace_version, active.version) {
                    return Ok(Err(WorkspaceFileHostError::Unavailable));
                }
                Ok(operation(&active.handle))
            },
        )
        .map_err(|error| match error {
            ProjectWorkspaceRepositoryError::NotFound => WorkspaceFileHostError::NotFound,
            _ => WorkspaceFileHostError::Unavailable,
        })?
    }
}

impl WorkspaceFileProvider for RootAdmissionGateway {
    fn list_files(&self, principal: &str, request: &WorkspaceFileListRequest) -> Result<WorkspaceFilePage, WorkspaceFileHostError> {
        (principal == PRINCIPAL).then_some(()).ok_or(WorkspaceFileHostError::Forbidden)?;
        if sensitive_path(request.relative_path()) { return Err(WorkspaceFileHostError::Forbidden); }
        self.with_workspace_root(request.workspace_id(), |root| {
            let entries = root.list_relative(request.relative_path(), usize::from(request.limit())).map_err(|_| WorkspaceFileHostError::Unavailable)?;
            let items = entries.into_iter().filter(|entry| !sensitive_path(entry.relative_path())).map(|entry| {
                let kind = match entry.kind() { RootFileKind::File => WorkspaceFileKind::File, RootFileKind::Directory => WorkspaceFileKind::Directory };
                WorkspaceFileEntry::new(entry.relative_path(), kind, entry.size_bytes())
            }).collect::<Result<Vec<_>, _>>()?;
            WorkspaceFilePage::new(request.limit(), items)
        })
    }

    fn read_file(&self, principal: &str, request: &WorkspaceFileReadRequest) -> Result<WorkspaceFileContent, WorkspaceFileHostError> {
        (principal == PRINCIPAL).then_some(()).ok_or(WorkspaceFileHostError::Forbidden)?;
        if sensitive_path(request.relative_path()) { return Err(WorkspaceFileHostError::Forbidden); }
        self.with_workspace_root(request.workspace_id(), |root| {
            let content = root.read_text_relative(request.relative_path(), runne_api::MAX_WORKSPACE_FILE_CONTENT_BYTES).map_err(|_| WorkspaceFileHostError::Unavailable)?;
            WorkspaceFileContent::new(request.relative_path(), content.clone(), content.len() as u64)
        })
    }
}

fn sensitive_path(path: &str) -> bool {
    path.split('/').any(|part| matches!(part, ".git" | ".ssh" | ".env") || part.ends_with(".key") || part.ends_with(".pem"))
}

#[cfg(test)]
mod tests {
    use super::active_root_is_current;

    #[test]
    fn active_root_stays_current_as_the_workspace_advances() {
        assert!(active_root_is_current(1, 1));
        // The bind the admission authorized moves the store past its
        // expected version; the same root must keep serving reads.
        assert!(active_root_is_current(2, 1));
        assert!(active_root_is_current(4, 3));
        // A store at or below the admitted version is a rollback snapshot.
        assert!(!active_root_is_current(2, 3));
    }
}
