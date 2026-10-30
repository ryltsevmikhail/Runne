use super::*;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

pub(super) fn run(
    root: &File,
    args: &coding_arguments::CodingArguments,
) -> Result<Vec<u8>, &'static str> {
    let current_root = coding_fs::namespace_root(root)?;
    let cwd = coding_fs::open(&current_root, &args.path, O_PATH | libc::O_DIRECTORY)?;
    let mut command = Command::new(&args.argv[0]);
    command
        .args(&args.argv[1..])
        .current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| match error.raw_os_error() {
            Some(libc::EACCES) => "command_spawn_access",
            Some(libc::ENOENT) => "command_spawn_missing",
            Some(libc::EPERM) => "command_spawn_policy",
            _ => "command_spawn_other",
        })?;
    let collected = coding_process::collect(&mut child, args.timeout_ms)?;
    coding_process::receipt(collected)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "coding_cwd_tests.rs"]
mod cwd_tests;
