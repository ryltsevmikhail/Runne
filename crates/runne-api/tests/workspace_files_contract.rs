use runne_api::{
    WorkspaceFileEntry, WorkspaceFileHostError, WorkspaceFileKind, WorkspaceFileListRequest,
    WorkspaceFilePage, WorkspaceFileReadRequest,
};
use runne_domain::id::WorkspaceId;

#[test]
fn file_requests_accept_only_canonical_relative_paths() {
    let workspace = WorkspaceId::from_bytes([7; 16]);
    assert!(WorkspaceFileListRequest::new(workspace, "src/lib.rs", 50).is_ok());
    assert!(matches!(
        WorkspaceFileReadRequest::new(workspace, "../secret"),
        Err(WorkspaceFileHostError::InvalidPath)
    ));
    assert!(matches!(
        WorkspaceFileReadRequest::new(workspace, "/etc/passwd"),
        Err(WorkspaceFileHostError::InvalidPath)
    ));
}

#[test]
fn file_page_rejects_unbounded_or_incoherent_provider_output() {
    let workspace = WorkspaceId::from_bytes([8; 16]);
    let entry = WorkspaceFileEntry::new("README.md", WorkspaceFileKind::File, 12).unwrap();
    assert!(WorkspaceFilePage::new(1, vec![entry]).is_ok());
    assert!(matches!(
        WorkspaceFilePage::new(
            1,
            vec![
                WorkspaceFileEntry::new("a", WorkspaceFileKind::File, 1).unwrap(),
                WorkspaceFileEntry::new("b", WorkspaceFileKind::File, 1).unwrap(),
            ]
        ),
        Err(WorkspaceFileHostError::InvariantViolation)
    ));
    assert!(WorkspaceFileReadRequest::new(workspace, "README.md").is_ok());
}
