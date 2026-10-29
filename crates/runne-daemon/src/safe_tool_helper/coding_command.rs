use super::*;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn run(
    root: &File,
    args: &coding_arguments::CodingArguments,
) -> Result<Vec<u8>, &'static str> {
    let current_root = coding_fs::namespace_root(root)?;
    let cwd = coding_fs::open(&current_root, &args.path, O_PATH | libc::O_DIRECTORY)?;
    let mut command = Command::new(&args.argv[0]);
    command
        .args(&args.argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    #[cfg(target_os = "linux")]
    command.current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()));
    #[cfg(target_os = "macos")]
    {
        // macOS fdescfs entries are not directories, so enter the pinned
        // descriptor directly in the child before exec.
        let cwd_fd = cwd.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(cwd_fd) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| match error.raw_os_error() {
            Some(libc::EACCES) => "command_spawn_access",
            Some(libc::ENOENT) => "command_spawn_missing",
            Some(libc::EPERM) => "command_spawn_policy",
            _ => "command_spawn_other",
        })?;
    let mut stdout = child.stdout.take().ok_or("effect_started_command_output")?;
    let mut stderr = child.stderr.take().ok_or("effect_started_command_output")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            return Err("effect_started_command_output");
        }
    }
    let deadline = Instant::now() + Duration::from_millis(args.timeout_ms);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut truncated = false;
    let mut timed_out = false;
    let status = loop {
        drain(&mut stdout, &mut out, &mut truncated);
        drain(&mut stderr, &mut err, &mut truncated);
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(_) => {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                return Err("effect_started_command_wait");
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            timed_out = true;
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break child.wait().map_err(|_| "effect_started_command_wait")?;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // Descendants are not allowed to survive a command invocation. The outer
    // managed-area supervisor independently proves the complete cgroup empty.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    drain(&mut stdout, &mut out, &mut truncated);
    drain(&mut stderr, &mut err, &mut truncated);
    serde_json::to_vec(&serde_json::json!({
        "exit_code":status.code(),"timed_out":timed_out,"output_truncated":truncated,
        "stdout_base64":STANDARD.encode(out),"stderr_base64":STANDARD.encode(err)
    }))
    .map_err(|_| "effect_started_output_invalid")
}
fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>, truncated: &mut bool) {
    let mut buffer = [0u8; 1024];
    // Bound per-tick draining even while a child floods its pipes.
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let keep = count.min(2048usize.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&buffer[..keep]);
                *truncated |= keep < count;
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "coding_cwd_tests.rs"]
mod cwd_tests;
