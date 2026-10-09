use super::*;
#[path = "protected_runtime_tests/approval_crash.rs"]
pub mod approval_crash;
use runne_platform_desktop::permission_reauth_linux::{
    NativePermissionWarningMainThreadScheduler, NativePermissionWarningUiTask, PamCancellation,
    PamConversationHandler, PamInteractionError, PamMessageKind,
};
use runne_platform_desktop::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeLaunchSpec,
    ProtectedBundledRuntimeSupervisor,
};
use runne_runtime_client::{
    BindWorkspaceRootRequest, CommandIdentity, CreateProjectRequest, CreateWorkspaceRequest,
    ExistingWorkspaceRequest, PermissionModeCommandStatusV2, PermissionModeV1,
    ProjectTrustControlRequestDto, ProjectTrustDecisionDto, ProtectedRootAdmission,
};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn parsed(arguments: &[&str]) -> Result<PathBuf, CliError> {
    let state = parse_global_options(arguments.iter().map(OsString::from).collect())?;
    protected_runtime_owner::parse_invocation(state).map(|(path, _)| path)
}

#[test]
fn protected_runtime_root_is_an_explicit_permissions_alternative() {
    let root = parsed(&[
        "permissions",
        "--protected-runtime-root",
        "/tmp/runne-root",
        "status",
        "--workspace-id",
        "018f2e3a-7000-7000-8000-000000000001",
    ])
    .expect("explicit protected-root permission read parses");
    assert_eq!(root, PathBuf::from("/tmp/runne-root"));
}

#[test]
fn protected_runtime_root_rejects_profile_relative_root_and_non_permissions_commands() {
    assert!(matches!(
        parsed(&[
            "--profile",
            "/tmp/profile",
            "permissions",
            "--protected-runtime-root",
            "/tmp/root",
            "approvals",
            "list",
        ]),
        Err(CliError::Usage)
    ));
    assert!(matches!(
        parsed(&[
            "permissions",
            "--protected-runtime-root",
            "relative",
            "approvals",
            "list"
        ]),
        Err(CliError::Usage)
    ));
    assert!(matches!(
        parsed(&["conversation", "--protected-runtime-root", "/tmp/root"]),
        Err(CliError::Usage)
    ));
}

#[test]
fn protected_runtime_root_keeps_approval_response_on_existing_confirmation_path() {
    assert_eq!(
        parsed(&[
            "permissions",
            "--protected-runtime-root",
            "/tmp/root",
            "approvals",
            "respond",
            "--approval-id",
            "018f2e3a-7000-7000-8000-000000000001",
            "--decision",
            "approve",
            "--command-id",
            "018f2e3a-7000-7000-8000-000000000002",
            "--idempotency-key",
            "same-command-key",
        ])
        .expect("approval response parses for protected owner"),
        PathBuf::from("/tmp/root")
    );
}

struct RefuseNativeUi;

impl NativePermissionWarningMainThreadScheduler for RefuseNativeUi {
    fn schedule(&self, _: NativePermissionWarningUiTask) -> Result<(), ()> {
        Err(())
    }
}

impl PamConversationHandler for RefuseNativeUi {
    fn present(
        &self,
        _: PamMessageKind,
        _: &str,
        _: &PamCancellation,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PamInteractionError> {
        Err(PamInteractionError::Cancelled)
    }
}

/// Child entry uses the real protected CLI owner and daemon; native evidence is
/// supplied only by the existing cfg(test) mock-authority API.
#[test]
fn protected_runtime_subprocess_entry() {
    let Ok(arguments) = std::env::var("RUNNE_CLI_OWNER_ARGS") else {
        return;
    };
    let arguments: Vec<String> = serde_json::from_str(&arguments).expect("child arguments");
    let arguments = arguments.into_iter().map(OsString::from).collect();
    let outcome = if std::env::var_os("RUNNE_CLI_OWNER_UI_ENTRY").is_some() {
        crate::run_entrypoint(arguments)
    } else {
        protected_runtime_owner::run(
            arguments,
            Arc::new(RefuseNativeUi),
            Arc::new(RefuseNativeUi),
        )
    };
    let result = serde_json::json!({
        "stdout": outcome.stdout,
        "stderr": outcome.stderr,
        "exitCode": outcome.exit_code,
    });
    std::fs::write(
        std::env::var_os("RUNNE_CLI_OWNER_RESULT").expect("child result path"),
        serde_json::to_vec(&result).expect("encode child result"),
    )
    .expect("write child result");
}

/// Test-only lifecycle barriers are inert unless the child test names one.
pub fn barrier(name: &str) {
    if std::env::var("RUNNE_CLI_OWNER_BARRIER").as_deref() != Ok(name) {
        return;
    }
    let directory =
        PathBuf::from(std::env::var_os("RUNNE_CLI_OWNER_BARRIER_DIR").expect("barrier directory"));
    std::fs::write(directory.join(format!("ready-{name}")), b"ready")
        .expect("publish lifecycle barrier");
    let deadline = Instant::now() + Duration::from_mins(3);
    while !directory.join(format!("release-{name}")).exists() {
        assert!(
            Instant::now() < deadline,
            "lifecycle barrier timed out: {name}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn record_mock_native_consent() {
    if let Some(path) = std::env::var_os("RUNNE_CLI_MOCK_NATIVE_LOG") {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("mock-native-consent log")
            .write_all(b"mock-native-consent\n")
            .expect("record mock-native-consent");
    }
}

pub fn mock_native_consent(
    runtime: &protected_runtime_owner::ProtectedPermissionsRuntime<'_>,
    expires_at_unix_ms: u64,
) -> Result<bool, ModeApiError> {
    super::permission_ceremony_deadline(expires_at_unix_ms).ok_or_else(unavailable_mode_error)?;
    let _ = (&runtime.scheduler, &runtime.pam);
    let mut supervisor = runtime
        .supervisor
        .lock()
        .map_err(|_| unavailable_mode_error())?;
    supervisor
        .test_complete_permission_mode_with_mock_native_authority()
        .map_err(|_| unavailable_mode_error())?;
    drop(supervisor);
    record_mock_native_consent();
    Ok(true)
}

struct Fixture {
    temporary: PathBuf,
    bundle: PathBuf,
    cli: PathBuf,
    daemon: PathBuf,
    root: PathBuf,
    home: PathBuf,
    state: PathBuf,
    mock_log: PathBuf,
    approval_mock_log: PathBuf,
    barrier_dir: PathBuf,
}

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).expect("create private fixture directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set private fixture permissions");
}

fn fixture() -> Fixture {
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
fn seed_workspace(fixture: &Fixture) -> (runne_runtime_client::CanonicalId, u64, String) {
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

fn command_arguments(
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

fn status_arguments(fixture: &Fixture, workspace: &str) -> Vec<String> {
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

fn command_status_arguments(fixture: &Fixture, workspace: &str, command: &str) -> Vec<String> {
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

fn spawn_cli(
    fixture: &Fixture,
    arguments: &[String],
    barrier_name: Option<&str>,
) -> (Child, PathBuf) {
    spawn_cli_with_entrypoint(fixture, arguments, barrier_name, false)
}

fn spawn_headless_entrypoint(fixture: &Fixture, arguments: &[String]) -> (Child, PathBuf) {
    spawn_cli_with_entrypoint(fixture, arguments, None, true)
}

fn spawn_cli_with_entrypoint(
    fixture: &Fixture,
    arguments: &[String],
    barrier_name: Option<&str>,
    ui_entrypoint: bool,
) -> (Child, PathBuf) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let result = fixture.barrier_dir.join(format!(
        "result-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut command = Command::new(&fixture.cli);
    if let Some(name) = barrier_name {
        for prefix in ["ready", "release"] {
            let marker = fixture.barrier_dir.join(format!("{prefix}-{name}"));
            match std::fs::remove_file(marker) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("clear prior lifecycle marker: {error}"),
            }
        }
    }
    command
        .args([
            "--exact",
            "protected_runtime_tests::protected_runtime_subprocess_entry",
            "--nocapture",
        ])
        .env(
            "RUNNE_CLI_OWNER_ARGS",
            serde_json::to_string(arguments).unwrap(),
        )
        .env("RUNNE_CLI_OWNER_RESULT", &result)
        .env("RUNNE_CLI_MOCK_NATIVE_LOG", &fixture.mock_log)
        .env("RUNNE_CLI_OWNER_BARRIER_DIR", &fixture.barrier_dir)
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.temporary.join("config"))
        .env("XDG_DATA_HOME", fixture.temporary.join("data"))
        .env("XDG_STATE_HOME", &fixture.state)
        .env_remove("RUNNE_CLI_OWNER_BARRIER")
        .env_remove("RUNNE_CLI_OWNER_UI_ENTRY")
        .env_remove("RUNNE_CLI_MOCK_APPROVAL_CONSENT")
        .env_remove("RUNNE_CLI_MOCK_APPROVAL_LOG");
    if ui_entrypoint {
        command
            .env("RUNNE_CLI_OWNER_UI_ENTRY", "1")
            .env("GDK_BACKEND", "x11")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY");
    }
    if let Some(name) = barrier_name {
        command.env("RUNNE_CLI_OWNER_BARRIER", name);
    }
    if arguments.iter().any(|argument| argument == "respond") {
        command
            .env("RUNNE_CLI_MOCK_APPROVAL_CONSENT", "approval-crash-fixture")
            .env("RUNNE_CLI_MOCK_APPROVAL_LOG", &fixture.approval_mock_log);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn copied CLI subprocess harness");
    (child, result)
}

fn child_output(child: Child) -> Output {
    child
        .wait_with_output()
        .expect("wait CLI subprocess harness")
}

fn result_value(output: &Output, path: &Path) -> serde_json::Value {
    assert!(
        output.status.success(),
        "subprocess harness failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(path).expect("CLI outcome artifact"))
        .expect("decode CLI outcome")
}

fn wait_barrier(mut child: Child, name: &str, directory: &Path, result_path: &Path) -> Child {
    let marker = directory.join(format!("ready-{name}"));
    let deadline = Instant::now() + Duration::from_mins(3);
    while !marker.exists() {
        if let Some(status) = child.try_wait().expect("poll CLI subprocess") {
            let output = child.wait_with_output().expect("read early CLI output");
            panic!(
                "CLI exited before {name} barrier ({status}): {}{}; outcome={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                std::fs::read_to_string(result_path).unwrap_or_else(|_| "<missing>".into())
            );
        }
        assert!(
            Instant::now() < deadline,
            "CLI did not reach {name} barrier"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn release_barrier(fixture: &Fixture, name: &str) {
    std::fs::write(
        fixture.barrier_dir.join(format!("release-{name}")),
        b"release",
    )
    .expect("release lifecycle barrier");
}

fn kill_child(mut child: Child) {
    child.kill().expect("SIGKILL barrier-held CLI child");
    let _ = child.wait().expect("reap CLI child");
}

fn assert_daemon_stops(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "protected daemon survived CLI crash"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn first_child_pid(pid: u32) -> u32 {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).expect("read CLI threads");
    let mut children = Vec::new();
    for task in tasks {
        if let Ok(list) = std::fs::read_to_string(task.expect("CLI thread").path().join("children"))
        {
            children.extend(
                list.split_whitespace()
                    .filter_map(|child| child.parse::<u32>().ok()),
            );
        }
    }
    assert_eq!(children.len(), 1, "CLI owns one adjacent protected daemon");
    children[0]
}

fn mock_consent_count(fixture: &Fixture) -> usize {
    std::fs::read_to_string(&fixture.mock_log)
        .unwrap_or_default()
        .lines()
        .count()
}

fn permission_witness_bytes(fixture: &Fixture) -> Vec<Vec<u8>> {
    let root = fixture.state.join("runne/cli/permission-intents");
    let Ok(scopes) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut paths = scopes
        .flat_map(|scope| {
            std::fs::read_dir(scope.expect("witness scope").path())
                .expect("read witness files")
                .map(Result::unwrap)
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| std::fs::read(path).expect("read witness bytes"))
        .collect()
}

fn permission_witnesses(fixture: &Fixture) -> Vec<serde_json::Value> {
    let root = fixture.state.join("runne/cli/permission-intents");
    let scopes = match std::fs::read_dir(&root) {
        Ok(scopes) => scopes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("read durable permission witness scope: {error}"),
    };
    scopes
        .flat_map(|scope| {
            std::fs::read_dir(scope.expect("witness scope").path())
                .expect("read witness files")
                .map(Result::unwrap)
        })
        .map(|entry| {
            serde_json::from_slice(
                &std::fs::read(entry.path()).expect("read saved permission witness"),
            )
            .expect("valid saved permission witness")
        })
        .collect()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one real subprocess scenario checks crash, reopen, lock, and replacement"
)]
fn protected_cli_real_process_recovery_and_single_owner_lifecycle() {
    let fixture = fixture();
    let (workspace, initial_revision, _) = seed_workspace(&fixture);
    let workspace = workspace.to_string();
    let mut revision = initial_revision;
    let mut last_committed = None;
    let (headless_read, read_result) =
        spawn_headless_entrypoint(&fixture, &status_arguments(&fixture, &workspace));
    let read = result_value(&child_output(headless_read), &read_result);
    assert_eq!(
        read["exitCode"], 0,
        "actual CLI entrypoint reads headlessly"
    );
    let status: serde_json::Value =
        serde_json::from_str(read["stdout"].as_str().expect("JSON status"))
            .expect("headless status JSON");
    assert_eq!(status["ok"], true);
    assert_eq!(status["data"]["authorizationRevision"], initial_revision);

    let unopened_command = runne_runtime_client::CanonicalId::now_v7().to_string();
    let (headless_mutation, mutation_result) = spawn_headless_entrypoint(
        &fixture,
        &command_arguments(
            &fixture,
            &workspace,
            &unopened_command,
            revision,
            "risk_based",
        ),
    );
    let mutation = result_value(&child_output(headless_mutation), &mutation_result);
    assert_ne!(
        mutation["exitCode"], 0,
        "mutation requires the native GTK path when display is unavailable"
    );
    assert!(permission_witnesses(&fixture).is_empty());
    assert_eq!(mock_consent_count(&fixture), 0);

    for (index, mode) in ["risk_based", "full_access", "ask_always"]
        .into_iter()
        .enumerate()
    {
        let before_post = runne_runtime_client::CanonicalId::now_v7().to_string();
        let consent_count = mock_consent_count(&fixture);
        let (interrupted, interrupted_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &before_post, revision, mode),
            Some("before_post"),
        );
        let interrupted_pid = interrupted.id();
        let interrupted = wait_barrier(
            interrupted,
            "before_post",
            &fixture.barrier_dir,
            &interrupted_result,
        );
        let witnesses = permission_witnesses(&fixture);
        assert_eq!(witnesses.len(), index * 2 + 1, "one pre-POST witness");
        assert!(
            witnesses
                .iter()
                .any(|witness| witness["commandId"] == before_post)
        );
        let daemon_pid = first_child_pid(interrupted_pid);
        kill_child(interrupted);
        assert_daemon_stops(daemon_pid);

        let (replay, replay_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &before_post, revision, mode),
            None,
        );
        let replay = result_value(&child_output(replay), &replay_result);
        let error: serde_json::Value =
            serde_json::from_str(replay["stderr"].as_str().expect("JSON error output"))
                .expect("permission replay error JSON");
        assert_eq!(replay["exitCode"], 5);
        assert_eq!(error["schemaVersion"], 1);
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "permission_command_unknown");
        assert_eq!(
            error["error"]["message"],
            format!("permission_command_unknown command_id={before_post}")
        );
        assert_eq!(mock_consent_count(&fixture), consent_count);

        let committed = runne_runtime_client::CanonicalId::now_v7().to_string();
        let (committing, committing_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &committed, revision, mode),
            Some("after_commit"),
        );
        let committing_pid = committing.id();
        let committing = wait_barrier(
            committing,
            "after_commit",
            &fixture.barrier_dir,
            &committing_result,
        );
        assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        let witnesses = permission_witnesses(&fixture);
        assert_eq!(
            witnesses.len(),
            index * 2 + 2,
            "one committed command witness"
        );
        assert!(
            witnesses
                .iter()
                .any(|witness| witness["commandId"] == committed)
        );
        let daemon_pid = first_child_pid(committing_pid);
        kill_child(committing);
        assert_daemon_stops(daemon_pid);

        if index == 0 {
            let (query, query_result) = spawn_headless_entrypoint(
                &fixture,
                &command_status_arguments(&fixture, &workspace, &committed),
            );
            let query = result_value(&child_output(query), &query_result);
            assert_eq!(query["exitCode"], 0, "headless command-status recovery");
            let envelope: serde_json::Value =
                serde_json::from_str(query["stdout"].as_str().expect("JSON command status"))
                    .expect("headless command-status JSON");
            assert_eq!(envelope["ok"], true);
            let mut data = envelope["data"].clone();
            data.as_object_mut()
                .expect("typed command data")
                .remove("nativeActionRequired");
            let status: PermissionModeCommandStatusV2 =
                serde_json::from_value(data).expect("canonical headless command status");
            let receipt = match status {
                PermissionModeCommandStatusV2::Committed { receipt } => receipt,
                other => panic!("expected committed headless status, got {other:?}"),
            };
            assert_eq!(receipt.command_id.to_string(), committed);
            assert_eq!(receipt.authorization_revision, revision + 1);
            assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        }

        let (reopen, reopen_result) = spawn_cli(
            &fixture,
            &command_arguments(&fixture, &workspace, &committed, revision, mode),
            None,
        );
        let reopened = result_value(&child_output(reopen), &reopen_result);
        assert_eq!(reopened["exitCode"], 0, "committed witness reopens");
        let envelope: serde_json::Value =
            serde_json::from_str(reopened["stdout"].as_str().expect("JSON success output"))
                .expect("committed receipt JSON");
        assert_eq!(envelope["schemaVersion"], 1);
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["data"]["state"], "committed");
        let mut data = envelope["data"].clone();
        data.as_object_mut()
            .expect("typed command data")
            .remove("nativeActionRequired");
        let status: PermissionModeCommandStatusV2 =
            serde_json::from_value(data).expect("canonical committed command status");
        let receipt = match status {
            PermissionModeCommandStatusV2::Committed { receipt } => receipt,
            other => panic!("expected committed receipt, got {other:?}"),
        };
        let expected_mode = match mode {
            "ask_always" => PermissionModeV1::AskAlways,
            "risk_based" => PermissionModeV1::RiskBased,
            "full_access" => PermissionModeV1::FullAccess,
            _ => unreachable!("closed mode list"),
        };
        assert_eq!(receipt.command_id.to_string(), committed);
        assert_eq!(
            receipt.idempotency_key,
            format!("protected-cli-{committed}")
        );
        assert_eq!(receipt.selected_mode, expected_mode);
        assert_eq!(receipt.authorization_revision, revision + 1);
        assert_eq!(receipt.history.selected_mode, expected_mode);
        assert_eq!(receipt.history.authorization_revision, revision + 1);
        assert_eq!(mock_consent_count(&fixture), consent_count + 1);
        revision += 1;
        last_committed = Some((committed, mode.to_owned(), reopened["stdout"].clone()));
    }

    let (committed, mode, expected_stdout) = last_committed.expect("three mode cases");
    let (normal, normal_result) = spawn_cli(
        &fixture,
        &command_arguments(&fixture, &workspace, &committed, revision - 1, &mode),
        None,
    );
    let normal = result_value(&child_output(normal), &normal_result);
    assert_eq!(normal["exitCode"], 0, "normal reopen succeeds");
    assert_eq!(normal["stdout"], expected_stdout, "same durable receipt");
    assert_eq!(mock_consent_count(&fixture), 3, "no repeat consent");

    let occupying_command = runne_runtime_client::CanonicalId::now_v7().to_string();
    let (owner, owner_result) = spawn_cli(
        &fixture,
        &command_arguments(
            &fixture,
            &workspace,
            &occupying_command,
            revision,
            "risk_based",
        ),
        Some("before_post"),
    );
    let owner_pid = owner.id();
    let owner = wait_barrier(owner, "before_post", &fixture.barrier_dir, &owner_result);
    let owner_daemon = first_child_pid(owner_pid);
    let (challenger, challenger_result) =
        spawn_cli(&fixture, &status_arguments(&fixture, &workspace), None);
    let challenger = result_value(&child_output(challenger), &challenger_result);
    assert_ne!(
        challenger["exitCode"], 0,
        "occupied root cannot be taken over"
    );
    assert!(Path::new(&format!("/proc/{owner_pid}")).exists());
    assert!(Path::new(&format!("/proc/{owner_daemon}")).exists());
    kill_child(owner);
    assert_daemon_stops(owner_daemon);

    let (replacing, result_path) = spawn_cli(
        &fixture,
        &status_arguments(&fixture, &workspace),
        Some("before_start"),
    );
    let replacing = wait_barrier(
        replacing,
        "before_start",
        &fixture.barrier_dir,
        &result_path,
    );
    let saved_daemon = fixture.bundle.join("runned.original");
    std::fs::rename(&fixture.daemon, &saved_daemon).expect("hold measured adjacent daemon");
    std::os::unix::fs::symlink("/usr/bin/false", &fixture.daemon)
        .expect("install adjacent replacement");
    release_barrier(&fixture, "before_start");
    let replaced = result_value(&child_output(replacing), &result_path);
    std::fs::remove_file(&fixture.daemon).expect("remove adjacent replacement");
    std::fs::rename(saved_daemon, &fixture.daemon).expect("restore original daemon");
    assert_ne!(
        replaced["exitCode"], 0,
        "replacement fails closed before daemon use"
    );
    std::fs::remove_dir_all(&fixture.temporary).expect("remove successful temporary fixture");
}
