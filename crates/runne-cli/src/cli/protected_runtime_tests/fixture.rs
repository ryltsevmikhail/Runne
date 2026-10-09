use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor,
};
use runne_runtime_client::{
    BindWorkspaceRootRequest, CommandIdentity, CreateProjectRequest, CreateWorkspaceRequest,
    ExistingWorkspaceRequest, ProjectTrustControlRequestDto, ProjectTrustDecisionDto,
    ProtectedRootAdmission,
};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) struct Fixture {
    pub(super) temporary: PathBuf,
    pub(super) bundle: PathBuf,
    pub(super) cli: PathBuf,
    pub(super) daemon: PathBuf,
    pub(super) root: PathBuf,
    pub(super) home: PathBuf,
    pub(super) state: PathBuf,
    pub(super) mock_log: PathBuf,
    pub(super) approval_mock_log: PathBuf,
    pub(super) barrier_dir: PathBuf,
}

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).expect("create private fixture directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set private fixture permissions");
}

pub(super) fn fixture() -> Fixture {
    let temporary = std::env::var_os("RUNNE_CLI_OWNER_ARTIFACT_ROOT")
        .map_or_else(
            || {
                let parent = PathBuf::from(std::env::var_os("HOME").expect("fixture HOME"));
                tempfile::Builder::new()
                    .prefix(".protected-cli-process-")
                    .tempdir_in(parent)
                    .expect("private fixture root")
            },
            |artifact_root| {
                tempfile::Builder::new()
                    .prefix(".protected-cli-process-")
                    .tempdir_in(artifact_root)
                    .expect("private fixture root")
            },
        )
        .keep();
    let bundle = temporary.join("bundle");
    private_directory(&bundle);
    let enrollment = bundle.join(".runne-native-enrollment");
    private_directory(&enrollment);
    let cli = bundle.join("runne-cli-test");
    std::fs::copy(std::env::current_exe().expect("test executable"), &cli)
        .expect("copy CLI test harness beside daemon");
    let daemon = bundle.join("runned");
    let target_daemon = std::env::current_exe()
        .expect("test executable")
        .parent()
        .and_then(Path::parent)
        .expect("target debug directory")
        .join("runned");
    assert!(
        target_daemon.is_file(),
        "build the protected runned fixture first"
    );
    std::fs::copy(target_daemon, &daemon).expect("copy protected daemon fixture");
    for executable in [&cli, &daemon] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("make copied test executable private");
    }
    let home = temporary.join("home");
    let state = temporary.join("state");
    let config = temporary.join("config");
    let data = temporary.join("data");
    let barrier_dir = temporary.join("barriers");
    for directory in [&home, &state, &config, &data, &barrier_dir] {
        private_directory(directory);
    }
    Fixture {
        root: bundle.join("runtime"),
        mock_log: temporary.join("mock-native-consent.log"),
        approval_mock_log: temporary.join("mock-approval-consent.log"),
        temporary,
        bundle,
        cli,
        daemon,
        home,
        state,
        barrier_dir,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one real daemon fixture seeds workspace trust for CLI lifecycle tests"
)]
pub(super) fn seed_workspace(
    fixture: &Fixture,
) -> (runne_runtime_client::CanonicalId, u64, String) {
    runne_platform_desktop::require_linux_cli_baseline_root(&fixture.root)
        .expect("baseline root before real daemon fixture");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(&fixture.daemon, &fixture.root)
        .expect("seed fixture launch spec");
    let mut owner =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    owner
        .start()
        .expect("start real protected daemon for workspace seed");
    let profile = owner
        .take_runtime_profile()
        .expect("one-time runtime profile");
    let runtime = tokio::runtime::Runtime::new().expect("seed runtime");
    let client = runtime
        .block_on(profile.connect(Duration::from_secs(30)))
        .expect("connect authenticated seed client");
    owner
        .record_client_ready(&client)
        .expect("record seed readiness");
    let project_id = runne_runtime_client::CanonicalId::now_v7();
    let project_command = runne_runtime_client::CanonicalId::now_v7();
    runtime
        .block_on(
            client.create_project(
                CreateProjectRequest::new(
                    CommandIdentity::new(
                        project_command,
                        format!("seed-project-{project_command}"),
                    )
                    .expect("project seed identity"),
                    project_id,
                    "protected CLI lifecycle fixture",
                )
                .expect("project seed request"),
            ),
        )
        .expect("create durable project in real daemon Store");
    let workspace_id = runne_runtime_client::CanonicalId::now_v7();
    let workspace_command = runne_runtime_client::CanonicalId::now_v7();
    runtime
        .block_on(
            client.create_workspace(
                CreateWorkspaceRequest::new(
                    CommandIdentity::new(
                        workspace_command,
                        format!("seed-workspace-{workspace_command}"),
                    )
                    .expect("workspace seed identity"),
                    project_id,
                    workspace_id,
                    "protected CLI lifecycle workspace",
                )
                .expect("workspace seed request"),
            ),
        )
        .expect("create durable workspace in real daemon Store");
    let workspace = runtime
        .block_on(client.get_workspace(workspace_id))
        .expect("read created durable workspace");
    if !workspace.is_open() {
        let open_command = runne_runtime_client::CanonicalId::now_v7();
        runtime
            .block_on(
                client.open_workspace(
                    ExistingWorkspaceRequest::new(
                        CommandIdentity::new(open_command, format!("seed-open-{open_command}"))
                            .expect("open workspace identity"),
                        workspace_id,
                        workspace.version(),
                    )
                    .expect("open workspace request"),
                ),
            )
            .expect("open real daemon workspace");
    }
    let workspace = runtime
        .block_on(client.get_workspace(workspace_id))
        .expect("read workspace before trusted root setup");
    let workspace_bytes = hex::decode(workspace_id.to_string().replace('-', ""))
        .expect("canonical workspace identity bytes");
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        workspace_bytes.try_into().expect("workspace UUID width"),
    );
    let project_root = fixture.temporary.join("project-root");
    private_directory(&project_root);
    let verified_root = runne_platform_desktop::VerifiedRootHandle::open(&project_root)
        .expect("open synthetic fixture project root");
    let admission = owner
        .prepare_root_admission(&verified_root, workspace_api_id, workspace.version())
        .expect("prepare synthetic fixture root admission");
    let admission = ProtectedRootAdmission::from_verified(admission)
        .expect("wrap protected fixture root admission");
    let bind_command = runne_runtime_client::CanonicalId::now_v7();
    let bind = BindWorkspaceRootRequest::new(
        CommandIdentity::new(bind_command, format!("seed-bind-{bind_command}"))
            .expect("fixture bind identity"),
        workspace_id,
        workspace.version(),
        &admission,
    )
    .expect("fixture bind request");
    runtime
        .block_on(client.bind_workspace_root(bind))
        .expect("bind synthetic fixture root");
    let trust = runtime
        .block_on(client.get_project_trust(project_id, workspace_id))
        .expect("read fixture project trust before explicit grant");
    assert!(trust.root_admission_version().is_some());
    let confirmed = runtime
        .block_on(client.decide_project_trust(ProjectTrustControlRequestDto {
            project_id,
            workspace_id,
            decision: ProjectTrustDecisionDto::ConfirmProject,
            expected_epoch: trust.epoch(),
            expected_revision: trust.revision(),
            expected_project_version: trust.project_version(),
            expected_workspace_version: trust.workspace_version(),
            expected_root_admission_version: trust.root_admission_version(),
        }))
        .expect("explicitly trust the synthetic fixture root");
    assert_eq!(
        confirmed.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let revision = runtime
        .block_on(client.permission_mode_status(workspace_id))
        .expect("read initial durable permission revision")
        .authorization_revision;
    let authority_id = client.session_info().authority_id.clone();
    drop(client);
    owner.stop().expect("stop and reap workspace seed daemon");
    (workspace_id, revision, authority_id)
}

pub(super) fn command_arguments(
    fixture: &Fixture,
    workspace: &str,
    command: &str,
    revision: u64,
    mode: &str,
) -> Vec<String> {
    vec![
        "--format".into(),
        "json".into(),
        "permissions".into(),
        "--protected-runtime-root".into(),
        fixture.root.to_string_lossy().into_owned(),
        "mode".into(),
        "set".into(),
        "--workspace-id".into(),
        workspace.into(),
        "--command-id".into(),
        command.into(),
        "--idempotency-key".into(),
        format!("protected-cli-{command}"),
        "--mode".into(),
        mode.into(),
        "--expected-revision".into(),
        revision.to_string(),
        "--preset-version".into(),
        "1".into(),
        "--expires-at-unix-ms".into(),
        "none".into(),
    ]
}

pub(super) fn status_arguments(fixture: &Fixture, workspace: &str) -> Vec<String> {
    vec![
        "--format".into(),
        "json".into(),
        "permissions".into(),
        "--protected-runtime-root".into(),
        fixture.root.to_string_lossy().into_owned(),
        "status".into(),
        "--workspace-id".into(),
        workspace.into(),
    ]
}

pub(super) fn command_status_arguments(
    fixture: &Fixture,
    workspace: &str,
    command: &str,
) -> Vec<String> {
    vec![
        "--format".into(),
        "json".into(),
        "permissions".into(),
        "--protected-runtime-root".into(),
        fixture.root.to_string_lossy().into_owned(),
        "command".into(),
        "status".into(),
        "--workspace-id".into(),
        workspace.into(),
        "--command-id".into(),
        command.into(),
    ]
}
