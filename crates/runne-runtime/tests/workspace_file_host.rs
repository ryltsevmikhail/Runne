use runne_api::{
    ApiPrincipalId, WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileHostPort,
    WorkspaceFileListRequest, WorkspaceFilePage, WorkspaceFileQueryContext,
    WorkspaceFileReadRequest,
};
use runne_application::ports::WorkspaceFileProvider;
use runne_domain::id::WorkspaceId;
use runne_runtime::RuntimeWorkspaceFileHost;

#[derive(Clone)]
struct Provider;

impl WorkspaceFileProvider for Provider {
    fn list_files(
        &self,
        principal: &str,
        request: &WorkspaceFileListRequest,
    ) -> Result<WorkspaceFilePage, WorkspaceFileHostError> {
        assert_eq!(principal, "local-owner");
        let item = runne_api::WorkspaceFileEntry::new(
            format!("{}/README.md", request.relative_path()),
            runne_api::WorkspaceFileKind::File,
            5,
        )?;
        WorkspaceFilePage::new(request.limit(), vec![item])
    }
    fn read_file(
        &self,
        principal: &str,
        request: &WorkspaceFileReadRequest,
    ) -> Result<WorkspaceFileContent, WorkspaceFileHostError> {
        assert_eq!(principal, "local-owner");
        WorkspaceFileContent::new(request.relative_path(), "hello".into(), 5)
    }
}

#[tokio::test]
async fn runtime_file_host_keeps_principal_and_returns_bounded_projections() {
    let host = RuntimeWorkspaceFileHost::new(Provider);
    let workspace = WorkspaceId::from_bytes([9; 16]);
    let page = host
        .list_files(
            WorkspaceFileQueryContext {
                principal: ApiPrincipalId::new("local-owner").unwrap(),
            },
            WorkspaceFileListRequest::new(workspace, "src", 10).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.items()[0].relative_path(), "src/README.md");
    let content = host
        .read_file(
            WorkspaceFileQueryContext {
                principal: ApiPrincipalId::new("local-owner").unwrap(),
            },
            WorkspaceFileReadRequest::new(workspace, "README.md").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content.content(), "hello");
    host.shutdown().await;
}
