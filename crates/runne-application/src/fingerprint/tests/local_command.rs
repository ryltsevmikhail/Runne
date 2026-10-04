#[test]
fn taskrun_local_command_changes_the_submit_fingerprint() {
    let conversation = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
    let workspace = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
    let text = runne_domain::task_run::TaskRunInput::new("run check".into()).unwrap();
    let command = runne_domain::task_run::TaskRunLocalCommand::new(
        runne_domain::task_run::TaskRunExecutable::workspace_relative("bin/check".into()).unwrap(),
        ".".into(),
        vec!["check".into()],
        vec![],
    )
    .unwrap();
    let local = text.clone().with_local_command(command).unwrap();
    assert_ne!(
        super::CommandFingerprint::for_submit(&conversation, &workspace, &text),
        super::CommandFingerprint::for_submit(&conversation, &workspace, &local),
    );
}
