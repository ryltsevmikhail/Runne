use super::*;
use runne_domain::project_workspace::MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES;

#[test]
fn transport_display_names_share_the_domain_bound_and_control_policy() {
    for value in [
        String::new(),
        "x".repeat(MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES + 1),
        "bad\u{0000}".into(),
        "bad\u{0085}".into(),
        "bad\u{00ad}".into(),
        "bad\u{061c}".into(),
        "bad\u{202e}".into(),
        "bad\u{2061}".into(),
        "bad\u{2066}".into(),
        "bad\u{e0001}".into(),
    ] {
        assert_eq!(
            ProjectWorkspaceDisplayNameInput::new(value),
            Err(ProjectWorkspaceHostError::Conflict)
        );
    }
    assert!(ProjectWorkspaceDisplayNameInput::new("Проект café".into()).is_ok());
}
