use super::*;
use std::ffi::OsString;
use std::path::PathBuf;

const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";

fn parsed_project_root(
    project_root: Option<&str>,
    tail: &[&str],
) -> Result<Option<PathBuf>, CliError> {
    let mut arguments = vec![
        OsString::from("permissions"),
        OsString::from("--protected-runtime-root"),
        OsString::from("/tmp/runne-root"),
    ];
    if let Some(project_root) = project_root {
        arguments.push(OsString::from("--project-root"));
        arguments.push(OsString::from(project_root));
    }
    arguments.extend(tail.iter().map(OsString::from));
    let state = parse_global_options(arguments)?;
    protected_runtime_owner::parse_invocation(state).map(|(_, command)| command.project_root)
}

#[test]
fn protected_runtime_project_root_parses_for_status_and_mode_set() {
    let status = parsed_project_root(
        Some("/tmp/runne-project"),
        &["status", "--workspace-id", WORKSPACE_ID],
    )
    .expect("status argv with --project-root parses");
    assert_eq!(status, Some(PathBuf::from("/tmp/runne-project")));

    let mode_set = parsed_project_root(
        Some("/tmp/runne-project"),
        &[
            "mode",
            "set",
            "--workspace-id",
            WORKSPACE_ID,
            "--command-id",
            "018f2e3a-7000-7000-8000-000000000002",
            "--idempotency-key",
            "ensure-parse-key",
            "--mode",
            "ask_always",
            "--expected-revision",
            "1",
            "--preset-version",
            "1",
            "--expires-at-unix-ms",
            "none",
        ],
    )
    .expect("mode set argv with --project-root parses");
    assert_eq!(mode_set, Some(PathBuf::from("/tmp/runne-project")));
}

#[test]
fn protected_runtime_project_root_requires_absolute_and_stays_optional() {
    assert!(matches!(
        parsed_project_root(
            Some("relative/project"),
            &["status", "--workspace-id", WORKSPACE_ID],
        ),
        Err(CliError::Usage)
    ));
    let legacy = parsed_project_root(None, &["status", "--workspace-id", WORKSPACE_ID])
        .expect("argv without --project-root keeps parsing");
    assert_eq!(legacy, None);
}
