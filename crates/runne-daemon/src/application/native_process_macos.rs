use super::{ActiveProcess, CapturedOutput, NativeOwnerBoundProcessLauncher, NativeProcessFiles};
use runne_security::broker::process::{
    OwnerBoundProcessError, OwnerBoundProcessLaunchRequest, ProcessLaunchObservationV1,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

const MAX_CAPTURE_BYTES: usize = 7 * 1024 * 1024;
const MAX_PROCARGS_BYTES: usize = 128 * 1024;
const LAUNCH_NONCE_ENV: &str = "RUNNE_PROCESS_LAUNCH_NONCE";

pub(super) fn spawn(
    launcher: &NativeOwnerBoundProcessLauncher,
    files: &NativeProcessFiles,
    request: &OwnerBoundProcessLaunchRequest<'_>,
) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
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
    let observation = ProcessLaunchObservationV1::new(pid, start_identity)?;
    let mut active = launcher
        .active
        .lock()
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
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
    Ok(observation)
}

pub(super) fn terminate(process: &mut ActiveProcess) -> Result<(), OwnerBoundProcessError> {
    if start_identity(process.pid)? != process.start_identity {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let pid = libc::pid_t::try_from(process.pid)
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    if unsafe { libc::getpgid(pid) } != pid {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    signal_group(pid, libc::SIGTERM)?;
    for _ in 0..200 {
        if process_exited(process)? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    signal_group(pid, libc::SIGKILL)?;
    if let Some(child) = process.child.as_mut() {
        child
            .wait()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    }
    Ok(())
}

pub(super) fn verify_re_adoption(
    handle: &runne_security::broker::process::OwnedProcessHandleV1,
) -> Result<(), OwnerBoundProcessError> {
    if start_identity(handle.pid())? != *handle.start_identity() {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let pid = libc::pid_t::try_from(handle.pid())
        .map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?;
    if unsafe { libc::getpgid(pid) } != pid {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let marker = process_launch_nonce(handle.pid())?;
    (marker == *handle.launch_nonce())
        .then_some(())
        .ok_or(OwnerBoundProcessError::OwnershipMismatch)
}

fn start_identity(pid: u32) -> Result<[u8; 32], OwnerBoundProcessError> {
    let pid =
        libc::pid_t::try_from(pid).map_err(|_| OwnerBoundProcessError::InvalidLaunchIdentity)?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .map_err(|_| OwnerBoundProcessError::InvalidLaunchIdentity)?;
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return Err(OwnerBoundProcessError::InvalidLaunchIdentity);
    }
    let info = unsafe { info.assume_init() };
    let mut digest = Sha256::new();
    digest.update(b"runne.macos-process-identity.v1");
    digest.update(pid.to_be_bytes());
    digest.update(info.pbi_start_tvsec.to_be_bytes());
    digest.update(info.pbi_start_tvusec.to_be_bytes());
    Ok(digest.finalize().into())
}

fn process_launch_nonce(pid: u32) -> Result<[u8; 16], OwnerBoundProcessError> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| OwnerBoundProcessError::OwnershipMismatch)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = 0_usize;
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || size == 0 || size > MAX_PROCARGS_BYTES {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let mut bytes = vec![0_u8; size];
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    parse_launch_nonce(&bytes[..size]).ok_or(OwnerBoundProcessError::OwnershipMismatch)
}

fn parse_launch_nonce(bytes: &[u8]) -> Option<[u8; 16]> {
    let argc = usize::try_from(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?)).ok()?;
    if argc == 0 || argc > 1024 {
        return None;
    }
    let mut cursor = 4_usize;
    for _ in 0..argc {
        let end = bytes.get(cursor..)?.iter().position(|byte| *byte == 0)?;
        cursor = cursor.checked_add(end + 1)?;
    }
    while bytes.get(cursor).is_some_and(|byte| *byte == 0) {
        cursor += 1;
    }
    for field in bytes.get(cursor..)?.split(|byte| *byte == 0) {
        let Some(value) = field.strip_prefix(LAUNCH_NONCE_ENV.as_bytes()) else {
            continue;
        };
        let Some(value) = value.strip_prefix(b"=") else {
            continue;
        };
        let Ok(decoded) = hex::decode(value) else {
            continue;
        };
        if let Ok(nonce) = <[u8; 16]>::try_from(decoded) {
            return Some(nonce);
        }
    }
    None
}

fn process_exited(process: &mut ActiveProcess) -> Result<bool, OwnerBoundProcessError> {
    if let Some(child) = process.child.as_mut() {
        return Ok(child
            .try_wait()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?
            .is_some());
    }
    Ok(start_identity(process.pid).is_err())
}

fn signal_group(pid: libc::pid_t, signal: libc::c_int) -> Result<(), OwnerBoundProcessError> {
    let result = unsafe { libc::kill(-pid, signal) };
    if result == 0
        || (result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
    {
        Ok(())
    } else {
        Err(OwnerBoundProcessError::LifecycleRejected)
    }
}

fn spawn_reader(
    reader: Option<impl Read + Send + 'static>,
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

#[cfg(test)]
mod tests {
    use super::{LAUNCH_NONCE_ENV, parse_launch_nonce};

    fn procargs(argv: &[&str], environment: &[&str]) -> Vec<u8> {
        let mut bytes = (argv.len() as i32).to_ne_bytes().to_vec();
        for value in argv.iter().chain(environment) {
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        bytes
    }

    #[test]
    fn parses_nonce_only_from_environment_after_argv() {
        let nonce = [7_u8; 16];
        let bytes = procargs(
            &["/bin/worker", "--marker", "ignored"],
            &[&format!("{LAUNCH_NONCE_ENV}={}", hex::encode(nonce))],
        );
        assert_eq!(parse_launch_nonce(&bytes), Some(nonce));
    }

    #[test]
    fn rejects_nonce_string_in_argv() {
        let nonce = [8_u8; 16];
        let bytes = procargs(
            &[&format!("{LAUNCH_NONCE_ENV}={}", hex::encode(nonce))],
            &[],
        );
        assert_eq!(parse_launch_nonce(&bytes), None);
    }

    #[test]
    fn rejects_malformed_procargs_and_nonce() {
        assert_eq!(parse_launch_nonce(&[1, 0, 0]), None);
        let bytes = procargs(&["/bin/worker"], &[&format!("{LAUNCH_NONCE_ENV}=bad")]);
        assert_eq!(parse_launch_nonce(&bytes), None);
    }
}
