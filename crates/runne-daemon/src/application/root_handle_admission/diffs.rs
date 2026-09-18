use runne_api::{
    WorkspaceChangeEntry, WorkspaceChangeKind, WorkspaceChangeListRequest, WorkspaceChangeSet,
    WorkspaceDiff, WorkspaceDiffHostError, WorkspaceDiffLine, WorkspaceDiffLineKind,
    WorkspaceDiffReadRequest,
};
use runne_application::ports::WorkspaceDiffProvider;

impl WorkspaceDiffProvider for RootAdmissionGateway {
    fn list_changes(
        &self,
        principal: &str,
        request: &WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError> {
        (principal == PRINCIPAL)
            .then_some(())
            .ok_or(WorkspaceDiffHostError::Forbidden)?;
        self.admit_workspace_source(request.workspace_id(), SourceChannel::FilesList, None)
            .map_err(TrustSourceError::into_diff)?;
        self.with_active_root(request.workspace_id(), |active| {
            let Some(baseline) = active.baseline.files() else {
                return Err(WorkspaceDiffHostError::Forbidden);
            };
            let current = capture_text_files(&active.handle).map_err(|_| WorkspaceDiffHostError::Unavailable)?;
            let mut entries = Vec::new();
            for (path, (before, after)) in changed_files(baseline, &current) {
                let (kind, additions, deletions) = change_summary(before, after);
                entries.push(
                    WorkspaceChangeEntry::new(path, kind, additions, deletions)
                        .map_err(|_| WorkspaceDiffHostError::InvariantViolation)?,
                );
                if entries.len() == usize::from(request.limit()) {
                    break;
                }
            }
            WorkspaceChangeSet::new(entries).map_err(|_| WorkspaceDiffHostError::InvariantViolation)
        })
    }

    fn read_diff(
        &self,
        principal: &str,
        request: &WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
        (principal == PRINCIPAL)
            .then_some(())
            .ok_or(WorkspaceDiffHostError::Forbidden)?;
        self.admit_workspace_source(
            request.workspace_id(),
            SourceChannel::FilesRead,
            Some(request.relative_path()),
        )
        .map_err(TrustSourceError::into_diff)?;
        self.with_active_root(request.workspace_id(), |active| {
            let Some(baseline) = active.baseline.files() else {
                return Err(WorkspaceDiffHostError::Forbidden);
            };
            let current = capture_text_files(&active.handle).map_err(|_| WorkspaceDiffHostError::Unavailable)?;
            let before = baseline.get(request.relative_path()).map(String::as_str);
            let after = current.get(request.relative_path()).map(String::as_str);
            if before.is_none() && after.is_none() {
                return Err(WorkspaceDiffHostError::NotFound);
            }
            replacement_diff(request.relative_path(), before, after)
        })
    }
}

impl RootAdmissionGateway {
    fn with_active_root<T>(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
        operation: impl FnOnce(&ActiveRoot) -> Result<T, WorkspaceDiffHostError>,
    ) -> Result<T, WorkspaceDiffHostError> {
        let Some(authority) = &self.0 else {
            return Err(WorkspaceDiffHostError::Unavailable);
        };
        let result = authority
            .store
            .with_current_workspace_version(PRINCIPAL, workspace_id, |version| {
                let state = authority
                    .state
                    .lock()
                    .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                let active = state
                    .active
                    .get(&workspace_id)
                    .filter(|active| active.version == version)
                    .ok_or(runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                Ok(operation(active))
            })
            ;
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(match error {
                runne_application::ports::ProjectWorkspaceRepositoryError::NotFound => {
                    WorkspaceDiffHostError::NotFound
                }
                _ => WorkspaceDiffHostError::Unavailable,
            }),
        }
    }
}

fn replacement_diff(
    path: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
    let kind = match (before, after) {
        (None, Some(_)) => WorkspaceChangeKind::Added,
        (Some(_), None) => WorkspaceChangeKind::Deleted,
        _ => WorkspaceChangeKind::Modified,
    };
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    for (line_kind, content) in [
        (WorkspaceDiffLineKind::Removed, before),
        (WorkspaceDiffLineKind::Added, after),
    ] {
        if let Some(content) = content {
            for line in content.lines() {
                if lines.len() == runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK
                    || bytes.saturating_add(line.len()) > runne_api::MAX_WORKSPACE_DIFF_BYTES
                {
                    truncated = true;
                    break;
                }
                let value = WorkspaceDiffLine::new(line_kind, line)
                    .map_err(|_| WorkspaceDiffHostError::SizeLimit)?;
                bytes = bytes.saturating_add(value.text().len());
                lines.push(value);
            }
        }
        if truncated {
            break;
        }
    }
    let old_lines = lines.iter().filter(|line| line.kind() != WorkspaceDiffLineKind::Added).count();
    let new_lines = lines.iter().filter(|line| line.kind() != WorkspaceDiffLineKind::Removed).count();
    let hunk = runne_api::WorkspaceDiffHunk::new(
        1,
        u32::try_from(old_lines).map_err(|_| WorkspaceDiffHostError::SizeLimit)?,
        1,
        u32::try_from(new_lines).map_err(|_| WorkspaceDiffHostError::SizeLimit)?,
        lines,
    )
    .map_err(|_| WorkspaceDiffHostError::InvariantViolation)?;
    WorkspaceDiff::new(path, kind, vec![hunk], truncated)
        .map_err(|_| WorkspaceDiffHostError::InvariantViolation)
}

#[cfg(test)]
mod diff_tests {
    use super::replacement_diff;
    use runne_api::{WorkspaceChangeKind, WorkspaceDiffLineKind};

    #[test]
    fn replacement_diff_produces_bounded_structured_hunk() {
        let diff = replacement_diff("src/main.rs", Some("old\n"), Some("new\nline\n"))
            .expect("valid replacement");
        assert_eq!(diff.path(), "src/main.rs");
        assert_eq!(diff.kind(), WorkspaceChangeKind::Modified);
        assert_eq!(diff.hunks()[0].old_lines(), 1);
        assert_eq!(diff.hunks()[0].new_lines(), 2);
        assert_eq!(diff.hunks()[0].lines()[0].kind(), WorkspaceDiffLineKind::Removed);
        assert_eq!(diff.hunks()[0].lines()[2].text(), "line");
        assert!(!diff.truncated());
    }

    #[test]
    fn replacement_diff_truncates_at_the_per_hunk_limit() {
        let content = std::iter::repeat_n("line", runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK + 1)
            .collect::<Vec<_>>()
            .join("\n");
        let diff = replacement_diff("src/large.rs", Some(&content), None)
            .expect("bounded replacement");
        assert!(diff.truncated());
        assert_eq!(
            diff.hunks()[0].lines().len(),
            runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK
        );
    }
}
