use super::{ActiveProcess, CapturedOutput, NativeOwnerBoundProcessLauncher, NativeProcessFiles};
use runne_security::broker::process::{
    OwnedProcessHandleV1, OwnerBoundProcessError, OwnerBoundProcessLaunchRequest,
    ProcessLaunchObservationV1,
};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, FILETIME, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, OpenJobObjectW,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    GetProcessTimes, INFINITE, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};

const MAX_CAPTURE_BYTES: usize = 7 * 1024 * 1024;
const LAUNCH_NONCE_ENV: &str = "RUNNE_PROCESS_LAUNCH_NONCE";

/// Handles and pipes retained for one suspended, job-bound Windows child.
pub(super) struct WindowsChild {
    process: OwnedHandle,
    job: OwnedHandle,
    stdout: Option<File>,
    stderr: Option<File>,
}

// Windows kernel handles are movable ownership tokens; all access remains
// serialized through ActiveProcess and the OS closes them exactly once.
unsafe impl Send for WindowsChild {}

pub(super) fn spawn(
    launcher: &NativeOwnerBoundProcessLauncher,
    files: &NativeProcessFiles,
    request: &OwnerBoundProcessLaunchRequest<'_>,
) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
    let (mut child, pid, start_identity) = create_child(files, request)?;
    let output = Arc::new(Mutex::new(Vec::new()));
    spawn_reader(child.stdout.take(), false, Arc::clone(&output));
    spawn_reader(child.stderr.take(), true, Arc::clone(&output));
    let observation = ProcessLaunchObservationV1::new(pid, start_identity)?;
    let mut active = launcher
        .active
        .lock()
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    if active.contains_key(&pid) {
        terminate_child(&mut child)?;
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

fn create_child(
    files: &NativeProcessFiles,
    request: &OwnerBoundProcessLaunchRequest<'_>,
) -> Result<(WindowsChild, u32, [u8; 32]), OwnerBoundProcessError> {
    let executable_path = files.executable_command_path();
    let cwd_path = files.cwd_command_path();
    let executable = wide_path(&executable_path)?;
    let cwd = wide_path(&cwd_path)?;
    let mut command = command_line(&executable_path, request.argv())?;
    let environment = environment_block(request)?;
    let (stdout_read, stdout_write) = pipe_pair()?;
    let (stderr_read, stderr_write) = match pipe_pair() {
        Ok(pair) => pair,
        Err(error) => {
            close_raw(stdout_read);
            close_raw(stdout_write);
            return Err(error);
        }
    };
    let startup = STARTUPINFOW {
        cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>())
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: stdout_write,
        hStdError: stderr_write,
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &raw const startup,
            &mut information,
        )
    };
    unsafe {
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);
    }
    if created == 0 {
        close_raw(stdout_read);
        close_raw(stderr_read);
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    let process = own(information.hProcess);
    let thread = own(information.hThread);
    let job = match create_job(request.launch_nonce()) {
        Ok(job) => job,
        Err(error) => {
            terminate_raw(process.as_raw_handle() as HANDLE);
            close_raw(stdout_read);
            close_raw(stderr_read);
            return Err(error);
        }
    };
    if unsafe {
        AssignProcessToJobObject(
            job.as_raw_handle() as HANDLE,
            process.as_raw_handle() as HANDLE,
        )
    } == 0
    {
        terminate_raw(process.as_raw_handle() as HANDLE);
        close_raw(stdout_read);
        close_raw(stderr_read);
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX {
        terminate_raw(process.as_raw_handle() as HANDLE);
        close_raw(stdout_read);
        close_raw(stderr_read);
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    let start_identity =
        match process_identity(process.as_raw_handle() as HANDLE, information.dwProcessId) {
            Ok(identity) => identity,
            Err(error) => {
                terminate_raw(process.as_raw_handle() as HANDLE);
                close_raw(stdout_read);
                close_raw(stderr_read);
                return Err(error);
            }
        };
    let stdout = unsafe { File::from_raw_handle(stdout_read as _) };
    let stderr = unsafe { File::from_raw_handle(stderr_read as _) };
    Ok((
        WindowsChild {
            process,
            job,
            stdout: Some(stdout),
            stderr: Some(stderr),
        },
        information.dwProcessId,
        start_identity,
    ))
}

fn create_job(nonce: &[u8; 16]) -> Result<OwnedHandle, OwnerBoundProcessError> {
    let name = wide_name(nonce);
    let job = unsafe { CreateJobObjectW(ptr::null(), name.as_ptr()) };
    if job.is_null() {
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        close_raw(job);
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    let job = own(job);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let size = u32::try_from(std::mem::size_of_val(&limits))
        .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
    let configured = unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            (&raw mut limits).cast::<std::ffi::c_void>(),
            size,
        )
    };
    (configured != 0)
        .then_some(job)
        .ok_or(OwnerBoundProcessError::LifecycleRejected)
}

pub(super) fn verify_re_adoption(
    handle: &OwnedProcessHandleV1,
) -> Result<(), OwnerBoundProcessError> {
    let process = open_process(
        handle.pid(),
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
    )?;
    if process_identity(process.as_raw_handle() as HANDLE, handle.pid())?
        != *handle.start_identity()
    {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    if unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 0) } != WAIT_TIMEOUT {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let name = wide_name(handle.launch_nonce());
    let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, name.as_ptr()) };
    if job.is_null() {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let job = own(job);
    let mut in_job = 0;
    let checked = unsafe {
        IsProcessInJob(
            process.as_raw_handle() as HANDLE,
            job.as_raw_handle() as HANDLE,
            &mut in_job,
        )
    };
    (checked != 0 && in_job != 0)
        .then_some(())
        .ok_or(OwnerBoundProcessError::OwnershipMismatch)
}

pub(super) fn terminate(process: &mut ActiveProcess) -> Result<(), OwnerBoundProcessError> {
    if let Some(child) = process.child.as_mut() {
        if process_identity(child.process.as_raw_handle() as HANDLE, process.pid)?
            != process.start_identity
        {
            return Err(OwnerBoundProcessError::OwnershipMismatch);
        }
        terminate_child(child)?;
        return Ok(());
    }
    let handle = open_process(
        process.pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
    )?;
    if process_identity(handle.as_raw_handle() as HANDLE, process.pid)? != process.start_identity {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let name = wide_name(&process.launch_nonce);
    let job = unsafe { OpenJobObjectW(JOB_OBJECT_TERMINATE, 0, name.as_ptr()) };
    if job.is_null() {
        return Err(OwnerBoundProcessError::OwnershipMismatch);
    }
    let job = own(job);
    let terminated = unsafe { TerminateJobObject(job.as_raw_handle() as HANDLE, 1) } != 0;
    if !terminated {
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    (unsafe { WaitForSingleObject(handle.as_raw_handle() as HANDLE, INFINITE) } == WAIT_OBJECT_0)
        .then_some(())
        .ok_or(OwnerBoundProcessError::LifecycleRejected)
}

fn terminate_child(child: &mut WindowsChild) -> Result<(), OwnerBoundProcessError> {
    let terminated = unsafe { TerminateJobObject(child.job.as_raw_handle() as HANDLE, 1) } != 0;
    if !terminated {
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    (unsafe { WaitForSingleObject(child.process.as_raw_handle() as HANDLE, INFINITE) }
        == WAIT_OBJECT_0)
        .then_some(())
        .ok_or(OwnerBoundProcessError::LifecycleRejected)
}

include!("native_process_windows/helpers.rs");
