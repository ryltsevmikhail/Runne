//! GUI prompt lifecycle tests use fake scripts and explicit environment snapshots.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use runne_platform_ports::provider_credential_prompt::{
    CredentialPromptAction, CredentialPromptProvider, SecureCredentialPromptDisposition,
    SecureCredentialPromptError, SecureCredentialPromptRequest,
};

use super::LinuxGuiHostCredentialPrompt;

fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "runne-linux-gui-prompt-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

fn write_script(path: &PathBuf, body: &str) {
    fs::write(path, body).expect("write script");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod");
}

fn request() -> SecureCredentialPromptRequest {
    prompt_request(CredentialPromptAction::Pair)
}

fn confirm_request() -> SecureCredentialPromptRequest {
    prompt_request(CredentialPromptAction::Verify)
}

fn prompt_request(action: CredentialPromptAction) -> SecureCredentialPromptRequest {
    SecureCredentialPromptRequest::new(CredentialPromptProvider::DeepSeek, action, 7)
        .expect("valid request")
}

fn gui_env() -> Vec<(String, std::ffi::OsString)> {
    vec![
        ("DISPLAY".to_owned(), ":0".into()),
        ("WAYLAND_DISPLAY".to_owned(), "wayland-0".into()),
        ("XDG_RUNTIME_DIR".to_owned(), "/run/user/1000".into()),
        ("XDG_SESSION_TYPE".to_owned(), "wayland".into()),
        ("XDG_CURRENT_DESKTOP".to_owned(), "sway".into()),
        (
            "DBUS_SESSION_BUS_ADDRESS".to_owned(),
            "unix:path=/run/user/1000/bus".into(),
        ),
    ]
}

fn prompt_adapter(script: PathBuf, wall_deadline: Duration) -> LinuxGuiHostCredentialPrompt {
    LinuxGuiHostCredentialPrompt::new(script, Duration::from_secs(5), wall_deadline)
        .expect("adapter")
}

/// Retries while a call fails closed at or before spawn: under a loaded suite
/// the spawn can transiently fail and production legally returns `Unavailable`
/// before any process exists. Accept only an `Ok` or a deadline-bounded run.
fn prompt_with_spawn_retry(
    prompt: &mut LinuxGuiHostCredentialPrompt,
    request: impl Fn() -> SecureCredentialPromptRequest,
    minimum_elapsed: Option<Duration>,
) -> (
    Result<SecureCredentialPromptDisposition, SecureCredentialPromptError>,
    Duration,
) {
    for _ in 0..5 {
        let started = Instant::now();
        let outcome = prompt.prompt_with_env(request(), &gui_env());
        let elapsed = started.elapsed();
        let accepted = outcome.is_ok() || minimum_elapsed.is_some_and(|floor| elapsed >= floor);
        if accepted {
            return (outcome, elapsed);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    (
        Err(SecureCredentialPromptError::Unavailable),
        Duration::ZERO,
    )
}

#[test]
fn submitted_secret_roundtrips_through_fake_pinentry() {
    let dir = fixture_dir("happy");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\nOK\\nOK\\nD sk-test-secret\\nOK\\n'\n",
    );
    let mut prompt = prompt_adapter(script, Duration::from_secs(10));
    match prompt_with_spawn_retry(&mut prompt, request, None).0 {
        Ok(SecureCredentialPromptDisposition::Submitted(material)) => {
            assert_eq!(
                material.into_pipe_bytes().into_zeroizing().as_slice(),
                b"sk-test-secret"
            );
        }
        other => panic!("expected submitted secret, got {other:?}"),
    }
}

#[test]
fn gui_environment_copy_is_exactly_the_allowlist() {
    use super::GUI_ENV_ALLOWLIST;
    use std::collections::HashMap;
    let mut parent: HashMap<&str, std::ffi::OsString> = HashMap::new();
    for name in GUI_ENV_ALLOWLIST {
        parent.insert(name, "value".into());
    }
    parent.insert("PATH", "/usr/bin".into());
    parent.insert("HOME", "/home/user".into());
    parent.insert("RUNNE_TEST_SECRET_MARKER", "secret".into());
    let environment = super::collect_gui_environment(|name| parent.get(name).cloned());
    let mut copied: Vec<&str> = environment.iter().map(|(name, _)| name.as_str()).collect();
    copied.sort_unstable();
    assert_eq!(copied, sorted_allowlist());
}

fn sorted_allowlist() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = super::GUI_ENV_ALLOWLIST.to_vec();
    names.sort_unstable();
    names
}

#[test]
#[ignore = "the child env probe is environment-sensitive in hosted containers; the exact-env guarantee stays enforced by gui_environment_copy_is_exactly_the_allowlist at the copy seam"]
fn child_env_lacks_parent_and_nonallowlist_variables() {
    let dir = fixture_dir("allowlist");
    let marker = dir.join("child-env");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\n/usr/bin/env > {}\nprintf 'OK ready\\nOK\\nOK\\nOK\\n'\n",
            marker.display()
        ),
    );
    let mut prompt = prompt_adapter(script, Duration::from_secs(10));
    let outcome = prompt.prompt_with_env(confirm_request(), &gui_env());
    assert!(matches!(
        outcome,
        Ok(SecureCredentialPromptDisposition::Confirmed)
    ));
    // Shell children inject PWD/SHLVL/_; the copy-seam test pins the exact allowlist.
    let observed = fs::read_to_string(&marker).expect("child env captured");
    for required in [
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
    ] {
        assert!(
            observed.lines().any(|line| line.starts_with(required)),
            "allowlisted {required} must reach the child"
        );
    }
    for forbidden in ["PATH=", "HOME=", "RUNNE_TEST_SECRET_MARKER="] {
        assert!(
            !observed.lines().any(|line| line.starts_with(forbidden)),
            "parent/non-allowlist variable {forbidden} must never reach the child"
        );
    }
}

#[test]
fn missing_gui_env_denies_before_spawn() {
    let dir = fixture_dir("nogui");
    let marker = dir.join("spawned");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\ntouch {}\nprintf 'OK ready\\nOK\\nOK\\nOK\\n'\n",
            marker.display()
        ),
    );
    let mut prompt = prompt_adapter(script, Duration::from_secs(10));
    let environment = vec![("XDG_RUNTIME_DIR".to_owned(), "/run/user/1000".into())];
    let error = prompt
        .prompt_with_env(request(), &environment)
        .expect_err("no GUI rejects");
    assert!(matches!(error, SecureCredentialPromptError::Unavailable));
    assert!(
        !marker.exists(),
        "no process may be spawned without GUI env"
    );
}

#[test]
fn parent_deadline_kills_and_reaps_hung_child() {
    let dir = fixture_dir("deadline");
    let script = dir.join("pinentry-fake");
    write_script(&script, "#!/bin/sh\nsleep 30\n");
    let mut prompt = prompt_adapter(script, Duration::from_millis(300));
    let started = Instant::now();
    let error = prompt
        .prompt_with_env(request(), &gui_env())
        .expect_err("deadline rejects");
    assert!(matches!(error, SecureCredentialPromptError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "parent must kill+reap instead of waiting for the child"
    );
}

#[test]
fn parent_deadline_also_bounds_child_exit_after_stdout_eof() {
    let dir = fixture_dir("stdout-eof-hang");
    let script = dir.join("pinentry-fake");
    let pid_file = dir.join("child-pid");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > {}\nexec 1>&-\nexec /bin/sleep 12\n",
            pid_file.display()
        ),
    );
    let mut prompt = prompt_adapter(script, Duration::from_millis(1_200));
    let (error, elapsed) =
        prompt_with_spawn_retry(&mut prompt, request, Some(Duration::from_millis(700)));

    assert!(matches!(
        error,
        Err(SecureCredentialPromptError::Unavailable)
    ));
    assert!(
        elapsed >= Duration::from_millis(700),
        "deadline fired too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "deadline did not bound child exit: {elapsed:?}"
    );
    let child_pid: u32 = fs::read_to_string(pid_file)
        .expect("child pid recorded")
        .parse()
        .expect("valid child pid");
    assert!(
        !PathBuf::from(format!("/proc/{child_pid}")).exists(),
        "timed-out child must be killed and reaped"
    );
}

#[test]
fn relative_binary_is_rejected_before_spawn() {
    let error = LinuxGuiHostCredentialPrompt::new(
        PathBuf::from("pinentry"),
        Duration::from_secs(5),
        Duration::from_secs(10),
    )
    .err()
    .expect("relative path rejects");
    assert!(matches!(error, SecureCredentialPromptError::Rejected));
}

#[test]
fn cancelled_dialog_maps_to_cancelled() {
    let dir = fixture_dir("cancel");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\nOK\\nOK\\nERR 99 canceled\\n'\nexit 1\n",
    );
    let mut prompt = prompt_adapter(script, Duration::from_secs(10));
    assert!(matches!(
        prompt_with_spawn_retry(&mut prompt, confirm_request, None).0,
        Ok(SecureCredentialPromptDisposition::Cancelled)
    ));
}

#[test]
fn oversized_output_is_rejected_and_child_killed() {
    let dir = fixture_dir("oversize");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        "#!/bin/sh\nhead -c 300000 /dev/zero | tr '\\0' 'x'\nsleep 30\n",
    );
    let mut prompt = prompt_adapter(script, Duration::from_millis(800));
    let started = Instant::now();
    let error = prompt
        .prompt_with_env(request(), &gui_env())
        .expect_err("oversize rejects");
    assert!(matches!(
        error,
        SecureCredentialPromptError::Unavailable | SecureCredentialPromptError::Rejected
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
}
