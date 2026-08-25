use runne_api::{
    ApiPrincipalId, WorkspaceChangeEntry, WorkspaceChangeKind, WorkspaceChangeListRequest,
    WorkspaceChangeSet, WorkspaceDiff, WorkspaceDiffHostError, WorkspaceDiffHostPort,
    WorkspaceDiffHunk, WorkspaceDiffLine, WorkspaceDiffLineKind, WorkspaceDiffQueryContext,
    WorkspaceDiffReadRequest,
};
use runne_application::ports::WorkspaceDiffProvider;
use runne_runtime::RuntimeWorkspaceDiffHost;

#[derive(Clone)]
struct Provider;

impl WorkspaceDiffProvider for Provider {
    fn list_changes(
        &self,
        _: &str,
        request: &WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError> {
        let entry = WorkspaceChangeEntry::new("src/main.rs", WorkspaceChangeKind::Modified, 1, 1)
            .expect("entry");
        (request.limit() >= 1)
            .then(|| WorkspaceChangeSet::new(vec![entry]).expect("set"))
            .ok_or(WorkspaceDiffHostError::InvalidLimit)
    }

    fn read_diff(
        &self,
        _: &str,
        request: &WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
        let hunk = WorkspaceDiffHunk::new(
            1,
            1,
            1,
            1,
            vec![
                WorkspaceDiffLine::new(WorkspaceDiffLineKind::Removed, "old").unwrap(),
                WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "new").unwrap(),
            ],
        )
        .unwrap();
        WorkspaceDiff::new(
            request.relative_path(),
            WorkspaceChangeKind::Modified,
            vec![hunk],
            false,
        )
        .map_err(|_| WorkspaceDiffHostError::InvariantViolation)
    }
}

#[tokio::test]
async fn host_binds_principal_and_returns_bounded_provider_projections() {
    let workspace = runne_api::WorkspaceId::parse("018f2e3a-7000-7000-8000-000000000202").unwrap();
    let host = RuntimeWorkspaceDiffHost::new(Provider);
    let context = WorkspaceDiffQueryContext {
        principal: ApiPrincipalId::new("desktop").unwrap(),
    };
    let changes = host
        .list_changes(
            context.clone(),
            WorkspaceChangeListRequest::new(workspace, 10).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(changes.entries()[0].path(), "src/main.rs");
    let diff = host
        .read_diff(
            context,
            WorkspaceDiffReadRequest::new(workspace, "src/main.rs").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(diff.hunks()[0].lines().len(), 2);
    host.shutdown().await;
}
