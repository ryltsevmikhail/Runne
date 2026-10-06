use super::x2_supervisor::{X2Observation, X2Outcome, supervise_gated_child};
use crate::safe_tool_helper::{
    BindingV1, IdentityV1, OutputError, ReceiptV1, VersionV1, parse_output,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use runne_application::permission_modes::{CompositeEffectScope, NativeScopeAdmissionReceipt};
use runne_platform::local_command_linux::{
    GatedLinuxChild, LinuxCommandContainmentV1, LinuxCommandExecutable, LinuxCommandOutputLimitsV1,
    LinuxCommandSpec, LinuxCompositeScopeAdmission, SealedExecutableSnapshot,
};
use runne_platform::process_managed_area::{
    LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding,
};
use runne_platform_desktop::LinuxCommandWorkspaceFiles;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};

#[path = "tool_executor/output_observation.rs"]
mod output_observation;
#[path = "tool_executor/run_helper.rs"]
mod run_helper;
pub(in crate::application) use run_helper::run_helper;

#[path = "tool_executor/target_snapshot.rs"]
mod target_snapshot;
pub(in crate::application) use target_snapshot::capture_existing_target_snapshot;

const TOOL_OPERATION_DEADLINE: Duration = Duration::from_secs(2);
const STDOUT_CAP: usize = 16 * 1024;
const STDERR_CAP: usize = 4 * 1024;

pub(in crate::application) fn preflight_helper(
    files: &LinuxCommandWorkspaceFiles,
) -> Result<(), HelperRunError> {
    let stage = crate::application::exec_taskrun_worker::provider::d2_stage;
    stage("effect_helper_preflight");
    let image = File::open("/proc/self/exe").map_err(|_| HelperRunError::Unavailable)?;
    let executable = SealedExecutableSnapshot::from_held_file(&image)
        .map_err(|_| HelperRunError::Unavailable)?;
    let spec = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&executable),
        workspace: files.workspace(),
        cwd: files.cwd(),
        argv: vec![
            OsString::from("runned"),
            OsString::from("--safe-tool-helper-v1"),
        ],
        env: Vec::new(),
    };
    spec.preflight().map_err(|_| HelperRunError::Unavailable)?;
    LinuxManagedAreaRoot::open_current_cgroup().map_err(|_| HelperRunError::Unavailable)?;
    stage("effect_helper_preflight_ok");
    Ok(())
}

pub(in crate::application) fn verify_helper_stdout(
    stdout: &[u8],
    expected_binding: &BindingV1,
    expected_operation: &str,
    expected_path: &str,
    expected_root: &IdentityV1,
) -> Result<(ReceiptV1, Vec<u8>), OutputError> {
    let receipt = parse_output(stdout)?;
    if receipt.binding != *expected_binding
        || receipt.operation != expected_operation
        || receipt.path != expected_path
        || receipt.root != *expected_root
    {
        return Err(OutputError::Invalid);
    }
    let bytes = STANDARD
        .decode(receipt.bytes_base64.as_bytes())
        .map_err(|_| OutputError::Invalid)?;
    Ok((receipt, bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::application) enum HelperRunError {
    Unavailable,
    Denied,
    Cancelled,
    TimedOut,
    Uncertain,
}

pub(in crate::application) struct HelperRunFailure {
    pub reason: HelperRunError,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub cleanup_proved: bool,
    pub child_spawned: bool,
    pub go_released: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub observed_bytes_overflowed: bool,
    pub stdout_eof: bool,
    pub stderr_eof: bool,
    pub exit_code: Option<i32>,
}

impl std::fmt::Debug for HelperRunFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HelperRunFailure")
            .field("reason", &self.reason)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .field("cleanup_proved", &self.cleanup_proved)
            .field("child_spawned", &self.child_spawned)
            .field("go_released", &self.go_released)
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .field("stdout_observed_bytes", &self.stdout_observed_bytes)
            .field("stderr_observed_bytes", &self.stderr_observed_bytes)
            .field("observed_bytes_overflowed", &self.observed_bytes_overflowed)
            .field("stdout_eof", &self.stdout_eof)
            .field("stderr_eof", &self.stderr_eof)
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

pub(in crate::application) fn new_area(
    root: &runne_platform::process_managed_area::LinuxManagedAreaRoot,
    taskrun: runne_domain::id::TaskRunId,
    attempt: runne_domain::id::AttemptId,
    invocation: [u8; 16],
) -> Result<LinuxManagedArea, HelperRunError> {
    let binding = ManagedAreaBinding::new(*taskrun.as_bytes(), *attempt.as_bytes(), invocation)
        .map_err(|_| HelperRunError::Unavailable)?;
    root.create_area(binding)
        .map_err(|_| HelperRunError::Unavailable)
}

pub(in crate::application) fn descriptor_identity(
    file: &File,
) -> Result<(u64, u64), HelperRunError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(HelperRunError::Unavailable);
    }
    Ok((stat.st_dev, stat.st_ino))
}

pub(in crate::application) fn capture_target_precondition(
    files: &LinuxCommandWorkspaceFiles,
    tool_name: &str,
    path: &str,
) -> Result<Option<VersionV1>, ()> {
    capture_target_precondition_inner(files, tool_name, path).map_err(|_| ())
}

fn capture_target_precondition_inner(
    files: &LinuxCommandWorkspaceFiles,
    tool_name: &str,
    path: &str,
) -> Result<Option<VersionV1>, HelperRunError> {
    let path = std::ffi::CString::new(path).map_err(|_| HelperRunError::Denied)?;
    let fd = unsafe {
        libc::openat(
            files.workspace().as_raw_fd(),
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if tool_name == "workspace.file.create_new" && error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(HelperRunError::Denied);
    }
    if tool_name == "workspace.file.create_new" {
        unsafe { libc::close(fd) };
        return Err(HelperRunError::Denied);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as usize > 8 * 1024
    {
        return Err(HelperRunError::Denied);
    }
    Ok(Some(VersionV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: stat.st_size as u64,
        mtime_sec: stat.st_mtime,
        mtime_nsec: stat.st_mtime_nsec,
        ctime_sec: stat.st_ctime,
        ctime_nsec: stat.st_ctime_nsec,
    }))
}
