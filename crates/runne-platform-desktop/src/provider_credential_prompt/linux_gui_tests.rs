//! GUI host-prompt lifecycle tests (T7): env allowlist, pre-spawn denial,
//! bounded output, parent kill+reap deadline. Fake shell-script pinentry
//! fixtures only — the real pinentry binary and any real prompt are never
//! invoked, and tests use explicit env snapshots, never the runner's env.

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
    SecureCredentialPromptRequest::new(
        CredentialPromptProvider::DeepSeek,
        CredentialPromptAction::Pair,
        7,
    )
    .expect("valid request")
}

fn confirm_request() -> SecureCredentialPromptRequest {
    SecureCredentialPromptRequest::new(
        CredentialPromptProvider::DeepSeek,
        CredentialPromptAction::Verify,
        7,
    )
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

#[test]
fn submitted_secret_roundtrips_through_fake_pinentry() {
    let dir = fixture_dir("happy");
    let script = dir.join("pinentry-fake");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\nOK\\nOK\\nD sk-test-secret\\nOK\\n'\n",
    );
    let mut prompt =
        LinuxGuiHostCredentialPrompt::new(script, Duration::from_secs(5), Duration::from_secs(10))
            .expect("adapter");
    match prompt.prompt_with_env(request(), gui_env()) {
        Ok(SecureCredentialPromptDisposition::Submitted(material)) => {
            assert_eq!(material.into_pipe_bytes().as_bytes(), b"sk-test-secret");
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
    assert_eq!(
        copied,
        GUI_ENV_ALLOWLIST
            .len()
            .checked_div(1)
            .map(|_| sorted_allowlist())
            .unwrap()
    );
}

fn sorted_allowlist() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = super::GUI_ENV_ALLOWLIST.to_vec();
    names.sort_unstable();
    names
}

#[test]
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
    let mut prompt =
        LinuxGuiHostCredentialPrompt::new(script, Duration::from_secs(5), Duration::from_secs(10))
            .expect("adapter");
    let outcome = prompt.prompt_with_env(confirm_request(), gui_env());
    assert!(matches!(
        outcome,
        Ok(SecureCredentialPromptDisposition::Confirmed)
    ));
    // Shell children inject PWD/SHLVL/_ themselves, so this protocol fixture
    // is not an exact-env oracle; the exact set is proven at the copy seam
    // (gui_environment_copy_is_exactly_the_allowlist). This test pins that the
    // parent never contributes PATH, HOME, or any secret variable.
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
    let mut prompt =
        LinuxGuiHostCredentialPrompt::new(script, Duration::from_secs(5), Duration::from_secs(10))
            .expect("adapter");
    let environment = vec![("XDG_RUNTIME_DIR".to_owned(), "/run/user/1000".into())];
    let error = prompt
        .prompt_with_env(request(), environment)
        .err()
        .expect("no GUI rejects");
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
    let mut prompt = LinuxGuiHostCredentialPrompt::new(
        script,
        Duration::from_secs(5),
        Duration::from_millis(300),
    )
    .expect("adapter");
    let started = Instant::now();
    let error = prompt
        .prompt_with_env(request(), gui_env())
        .err()
        .expect("deadline rejects");
    assert!(matches!(error, SecureCredentialPromptError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "parent must kill+reap instead of waiting for the child"
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
    let mut prompt =
        LinuxGuiHostCredentialPrompt::new(script, Duration::from_secs(5), Duration::from_secs(10))
            .expect("adapter");
    assert!(matches!(
        prompt.prompt_with_env(request(), gui_env()),
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
    let mut prompt = LinuxGuiHostCredentialPrompt::new(
        script,
        Duration::from_secs(5),
        Duration::from_millis(800),
    )
    .expect("adapter");
    let started = Instant::now();
    let error = prompt
        .prompt_with_env(request(), gui_env())
        .err()
        .expect("oversize rejects");
    assert!(matches!(
        error,
        SecureCredentialPromptError::Unavailable | SecureCredentialPromptError::Rejected
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
}
