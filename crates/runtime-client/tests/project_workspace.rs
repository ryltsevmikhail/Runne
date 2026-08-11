use gocode_runtime_client::{
    BindWorkspaceRootRequest, CanonicalId, CommandIdentity, CreateProjectRequest,
    ExistingProjectRequest, REQUIRED_RUNTIME_CAPABILITIES, RootAdmissionToken, RuntimeApiErrorKind,
};

fn identity() -> CommandIdentity {
    CommandIdentity::new(
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000301").unwrap(),
        "project-workspace-test",
    )
    .unwrap()
}

fn id() -> CanonicalId {
    CanonicalId::parse("018f2e3a-7000-7000-8000-000000000302").unwrap()
}

#[test]
fn project_workspace_requests_reject_invalid_names_and_versions() {
    assert_eq!(
        CreateProjectRequest::new(identity(), id(), "\u{0000}")
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
    assert_eq!(
        ExistingProjectRequest::new(identity(), id(), 0)
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
}

#[test]
fn root_admission_token_is_opaque_redacted_and_v2_only() {
    let token = RootAdmissionToken::parse("gocode-root-admission-v2.abc_DEF-1").unwrap();
    assert_eq!(format!("{token:?}"), "RootAdmissionToken([REDACTED])");
    assert_eq!(
        RootAdmissionToken::parse("gocode-root-admission-v1.abc")
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::InvalidRequest
    );
    assert!(BindWorkspaceRootRequest::new(identity(), id(), 1, token).is_ok());
}

#[test]
fn capability_wave_is_exactly_required_by_the_client() {
    for capability in [
        "project.list.v1",
        "project.restore.v1",
        "workspace.bind_root.v2",
    ] {
        assert!(REQUIRED_RUNTIME_CAPABILITIES.contains(&capability));
    }
}
