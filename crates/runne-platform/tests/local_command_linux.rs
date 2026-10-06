#![cfg(target_os = "linux")]

use runne_platform::local_command_linux::{LinuxCommandError, LinuxCommandSpec};
use runne_platform::process_managed_area::{
    LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaError,
};
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "local_command_linux/confinement.rs"]
mod confinement;
#[path = "local_command_linux/io.rs"]
mod io;
#[path = "local_command_linux/permission.rs"]
mod permission;
#[path = "local_command_linux/signal.rs"]
mod signal;
#[path = "local_command_linux/snapshot_exec.rs"]
mod snapshot_exec;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
fn nonce() -> [u8; 16] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let mut id = [0; 16];
    id[..4].copy_from_slice(&std::process::id().to_be_bytes());
    id[4..8].copy_from_slice(&now.to_be_bytes()[12..]);
    id[8..].copy_from_slice(&NEXT_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    id
}
fn binding() -> (ManagedAreaBinding, [u8; 48]) {
    let task = [31; 16];
    let attempt = [32; 16];
    let unique = nonce();
    let binding = ManagedAreaBinding::new(task, attempt, unique).expect("binding");
    let mut fields = [0; 48];
    fields[..16].copy_from_slice(&task);
    fields[16..32].copy_from_slice(&attempt);
    fields[32..].copy_from_slice(&unique);
    (binding, fields)
}
fn root() -> Option<LinuxManagedAreaRoot> {
    LinuxManagedAreaRoot::open_current_cgroup().ok()
}
fn scope() -> Option<PathBuf> {
    let row = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find(|line| line.starts_with("0::"))?
        .to_owned();
    let relative = row.strip_prefix("0::")?;
    if relative.is_empty() || relative == "/" || relative.split('/').any(|part| part == "..") {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
}
fn area(root: &LinuxManagedAreaRoot, binding: ManagedAreaBinding) -> Option<AreaGuard> {
    match root.create_area(binding) {
        Ok(area) => Some(AreaGuard(Some(area))),
        Err(ManagedAreaError::Unavailable) => None,
        Err(error) => panic!("area setup: {error}"),
    }
}
struct AreaGuard(Option<LinuxManagedArea>);
impl std::ops::Deref for AreaGuard {
    type Target = LinuxManagedArea;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("area")
    }
}
impl AreaGuard {
    fn remove(mut self) {
        self.0
            .take()
            .expect("area")
            .remove_empty()
            .expect("remove empty");
    }
}
impl Drop for AreaGuard {
    fn drop(&mut self) {
        if let Some(area) = self.0.take() {
            let _ = area.terminate(Duration::ZERO);
            let _ = area.remove_empty();
        }
    }
}
struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "runne-gate-{}-{:x}",
            std::process::id(),
            u128::from_be_bytes(nonce())
        ));
        std::fs::create_dir(&dir).expect("workspace temp");
        Self(dir)
    }
    fn file(&self) -> File {
        File::open(&self.0).expect("open workspace")
    }
    fn cwd(&self) -> File {
        File::open(&self.0).expect("open cwd")
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn spec<'a>(
    exe: &'a File,
    workspace: &'a File,
    cwd: &'a File,
    script: OsString,
    env: Vec<(OsString, OsString)>,
) -> LinuxCommandSpec<'a> {
    LinuxCommandSpec {
        executable: runne_platform::local_command_linux::LinuxCommandExecutable::HeldFile(exe),
        workspace,
        cwd,
        argv: vec![OsString::from("/bin/sh"), OsString::from("-c"), script],
        env,
    }
}
fn run_or_skip() -> Option<(LinuxManagedAreaRoot, AreaGuard, [u8; 48])> {
    let Some(root) = root() else {
        eprintln!("SKIP: delegated cgroup-v2 scope unavailable");
        return None;
    };
    let (binding, identity_bytes) = binding();
    let Some(area) = area(&root, binding) else {
        eprintln!("SKIP: private delegated child cgroup unavailable");
        return None;
    };
    Some((root, area, identity_bytes))
}

#[test]
fn cancellation_before_release_never_executes_user_command() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: cancellation_before_release_never_executes_user_command");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let exe = File::open("/bin/sh").expect("shell executable");
    let marker = workspace.0.join("must-not-exist");
    let script = OsString::from(format!("printf executed > '{}'", marker.display()));
    let env = Vec::new();
    let command = spec(&exe, &workspace_fd, &cwd, script, env);
    let child = command.spawn_gated(&area).expect("trusted stopped gate");
    assert!(area.is_populated().expect("area populated while gated"));
    child.cancel(Duration::ZERO).expect("cancel held gate");
    assert!(!marker.exists(), "user command must not run before release");
    assert!(!area.is_populated().expect("empty after cancel"));
    area.remove();
}

#[test]
fn invalid_workspace_is_refused_before_any_user_code() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: invalid_workspace_is_refused_before_any_user_code");
    let workspace = File::open("/").expect("root descriptor");
    let cwd = File::open("/").expect("root cwd");
    let exe = File::open("/bin/sh").expect("shell executable");
    let marker = std::env::temp_dir().join(format!("runne-gate-refused-{}", std::process::id()));
    let script = OsString::from(format!("printf executed > '{}'", marker.display()));
    let command = spec(&exe, &workspace, &cwd, script, Vec::new());
    assert_eq!(
        command.spawn_gated(&area).err(),
        Some(LinuxCommandError::Invalid)
    );
    assert!(!marker.exists());
    assert!(!area.is_populated().expect("still empty"));
    area.remove();
}

#[test]
fn cwd_descriptor_outside_workspace_is_rejected_before_user_code() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: cwd_descriptor_outside_workspace_is_rejected_before_user_code");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let parent = workspace.0.parent().expect("temp parent");
    let cwd = File::open(parent).expect("outside cwd");
    let exe = File::open("/bin/sh").expect("shell executable");
    let marker = workspace.0.join("cwd-must-not-run");
    let command = spec(
        &exe,
        &workspace_fd,
        &cwd,
        OsString::from(format!("printf executed > '{}'", marker.display())),
        Vec::new(),
    );
    assert_eq!(
        command.spawn_gated(&area).err(),
        Some(LinuxCommandError::Invalid)
    );
    assert!(!marker.exists());
    assert!(!area.is_populated().expect("still empty"));
    area.remove();
}

fn hex48(bytes: &[u8; 48]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
