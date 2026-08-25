use runne_api::{EditorLaunchTargetV1, OpenEditorRequest, WorkspaceEditorHostError};
use runne_domain::id::WorkspaceId;

fn workspace() -> WorkspaceId {
    "018f2e3a-7000-7000-8000-000000000401"
        .parse()
        .expect("fixture workspace id")
}

#[test]
fn editor_request_keeps_target_fixed_and_path_relative() {
    let request = OpenEditorRequest::new(
        workspace(),
        "src/main.rs",
        EditorLaunchTargetV1::SystemDefault,
    )
    .expect("scoped editor request");

    assert_eq!(request.workspace_id(), workspace());
    assert_eq!(request.relative_path(), "src/main.rs");
    assert_eq!(request.target(), EditorLaunchTargetV1::SystemDefault);
}

#[test]
fn editor_request_rejects_path_escape_and_empty_path() {
    for path in [
        "",
        "/tmp/main.rs",
        "../main.rs",
        "src/../main.rs",
        "src\\main.rs",
    ] {
        assert_eq!(
            OpenEditorRequest::new(workspace(), path, EditorLaunchTargetV1::SystemDefault)
                .expect_err("unsafe editor path must fail"),
            WorkspaceEditorHostError::InvalidPath,
            "path: {path}"
        );
    }
}
