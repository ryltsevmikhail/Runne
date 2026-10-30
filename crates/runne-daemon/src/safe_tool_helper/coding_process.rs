//! Bounded wait and receipt encoding shared by every command backend.

use super::*;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// Bounded output and exit state of one command invocation.
pub(super) struct Collected {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) truncated: bool,
    pub(super) timed_out: bool,
}

/// Waits for one already-spawned child while bounding both output streams and
/// killing the whole process group once it is done.
pub(super) fn collect(child: &mut Child, timeout_ms: u64) -> Result<Collected, &'static str> {
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
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
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
    Ok(Collected {
        status,
        stdout: out,
        stderr: err,
        truncated,
        timed_out,
    })
}

/// Encodes one invocation outcome exactly as the tool contract expects it.
pub(super) fn receipt(collected: Collected) -> Result<Vec<u8>, &'static str> {
    serde_json::to_vec(&serde_json::json!({
        "exit_code":collected.status.code(),"timed_out":collected.timed_out,
        "output_truncated":collected.truncated,
        "stdout_base64":STANDARD.encode(collected.stdout),
        "stderr_base64":STANDARD.encode(collected.stderr)
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
