use super::*;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub(super) fn spawn_cli(
    fixture: &Fixture,
    arguments: &[String],
    barrier_name: Option<&str>,
) -> (Child, PathBuf) {
    spawn_cli_with_entrypoint(fixture, arguments, barrier_name, false)
}

pub(super) fn spawn_headless_entrypoint(
    fixture: &Fixture,
    arguments: &[String],
) -> (Child, PathBuf) {
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

pub(super) fn child_output(child: Child) -> Output {
    child
        .wait_with_output()
        .expect("wait CLI subprocess harness")
}

pub(super) fn result_value(output: &Output, path: &Path) -> serde_json::Value {
    assert!(
        output.status.success(),
        "subprocess harness failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(path).expect("CLI outcome artifact"))
        .expect("decode CLI outcome")
}

pub(super) fn wait_barrier(
    mut child: Child,
    name: &str,
    directory: &Path,
    result_path: &Path,
) -> Child {
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

pub(super) fn release_barrier(fixture: &Fixture, name: &str) {
    std::fs::write(
        fixture.barrier_dir.join(format!("release-{name}")),
        b"release",
    )
    .expect("release lifecycle barrier");
}

pub(super) fn kill_child(mut child: Child) {
    child.kill().expect("SIGKILL barrier-held CLI child");
    let _ = child.wait().expect("reap CLI child");
}

pub(super) fn assert_daemon_stops(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "protected daemon survived CLI crash"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn first_child_pid(pid: u32) -> u32 {
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

pub(super) fn mock_consent_count(fixture: &Fixture) -> usize {
    std::fs::read_to_string(&fixture.mock_log)
        .unwrap_or_default()
        .lines()
        .count()
}

pub(super) fn permission_witness_bytes(fixture: &Fixture) -> Vec<Vec<u8>> {
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

pub(super) fn permission_witnesses(fixture: &Fixture) -> Vec<serde_json::Value> {
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
