use super::{ActiveProcess, CapturedOutput, NativeOwnerBoundProcessLauncher, NativeProcessFiles};
use runne_security::broker::process::{
    OwnerBoundProcessError, OwnerBoundProcessLaunchRequest, ProcessLaunchObservationV1,
};
use sha2::Digest;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const MAX_CAPTURE_BYTES: usize = 7 * 1024 * 1024;
pub(super) const LAUNCH_NONCE_ENV: &str = "RUNNE_PROCESS_LAUNCH_NONCE";

pub(super) fn spawn(
    launcher: &NativeOwnerBoundProcessLauncher,
    files: &NativeProcessFiles,
    request: &OwnerBoundProcessLaunchRequest<'_>,
) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(files.executable_command_path());
    command
        .args(request.argv())
        .current_dir(files.cwd_command_path())
        .env_clear()
        .envs(request.environment())
        .env(LAUNCH_NONCE_ENV, hex::encode(request.launch_nonce()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    let pid = child.id();
    let start_identity = match start_identity(pid) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let output = Arc::new(Mutex::new(Vec::new()));
    spawn_reader(child.stdout.take(), false, Arc::clone(&output));
    spawn_reader(child.stderr.take(), true, Arc::clone(&output));
    let Ok(observation) = ProcessLaunchObservationV1::new(pid, start_identity) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(OwnerBoundProcessError::InvalidLaunchIdentity);
    };
    let Ok(mut active) = launcher.active.lock() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(OwnerBoundProcessError::LifecycleRejected);
    };
    if active.contains_key(&pid) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    active.insert(
        pid,
        ActiveProcess {
            child: Some(child),
            pid,
            start_identity,
            launch_nonce: *request.launch_nonce(),
            output,
        },
    );
    drop(active);
    Ok(observation)
}

pub(super) fn verify_re_adoption(
    handle: &runne_security::broker::process::OwnedProcessHandleV1,
) -> Result<(), OwnerBoundProcessError> {
    if start_identity(handle.pid())? != *handle.start_identity() {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let pid = i32::try_from(handle.pid()).map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?;
    let pid =
        rustix::process::Pid::from_raw(pid).ok_or(OwnerBoundProcessError::OwnershipMismatch)?;
    if rustix::process::getpgid(Some(pid)).map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?
        != pid
    {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let marker = std::fs::read(format!("/proc/{}/environ", handle.pid()))
        .map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?
        .split(|byte| *byte == 0)
        .find_map(|entry| entry.strip_prefix(LAUNCH_NONCE_ENV.as_bytes()))
        .and_then(|entry| entry.strip_prefix(b"="))
        .and_then(|entry| hex::decode(entry).ok())
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        .ok_or(OwnerBoundProcessError::OwnershipMismatch)?;
    (marker == *handle.launch_nonce())
        .then_some(())
        .ok_or(OwnerBoundProcessError::OwnershipMismatch)
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: Option<R>,
    stderr: bool,
    output: Arc<Mutex<Vec<CapturedOutput>>>,
) {
    let Some(mut reader) = reader else { return };
    let _ = std::thread::Builder::new()
        .name("runne-process-output".into())
        .spawn(move || {
            let mut buffer = vec![0_u8; 64 * 1024];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let Ok(mut captured) = output.lock() else {
                    break;
                };
                let used = captured
                    .iter()
                    .map(|chunk| chunk.bytes.len())
                    .sum::<usize>();
                if used >= MAX_CAPTURE_BYTES {
                    break;
                }
                let take = read.min(MAX_CAPTURE_BYTES - used);
                captured.push(CapturedOutput {
                    stderr,
                    bytes: buffer[..take].to_vec(),
                });
            }
        });
}

pub(super) fn start_identity(pid: u32) -> Result<[u8; 32], OwnerBoundProcessError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| OwnerBoundProcessError::InvalidLaunchIdentity)?;
    let tail = stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(OwnerBoundProcessError::InvalidLaunchIdentity)?;
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .ok_or(OwnerBoundProcessError::InvalidLaunchIdentity)?;
    let mut digest = sha2::Sha256::new();
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    Ok(digest.finalize().into())
}

pub(super) fn terminate(process: &mut ActiveProcess) -> Result<(), OwnerBoundProcessError> {
    if start_identity(process_pid(process))? != process.start_identity {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let pid = i32::try_from(process_pid(process))
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    let pid =
        rustix::process::Pid::from_raw(pid).ok_or(OwnerBoundProcessError::LifecycleRejected)?;
    if rustix::process::getpgid(Some(pid)).map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?
        != pid
    {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    signal_group(pid, rustix::process::Signal::TERM)?;
    for _ in 0..200 {
        if process_exited(process)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    signal_group(pid, rustix::process::Signal::KILL)?;
    if let Some(child) = process.child.as_mut() {
        child
            .wait()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    }
    Ok(())
}

fn process_pid(process: &ActiveProcess) -> u32 {
    process.pid
}

fn process_exited(process: &mut ActiveProcess) -> Result<bool, OwnerBoundProcessError> {
    if let Some(child) = process.child.as_mut() {
        return Ok(child
            .try_wait()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?
            .is_some());
    }
    Ok(start_identity(process_pid(process)).is_err())
}

fn signal_group(
    pid: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), OwnerBoundProcessError> {
    match rustix::process::kill_process_group(pid, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(OwnerBoundProcessError::LifecycleRejected),
    }
}
