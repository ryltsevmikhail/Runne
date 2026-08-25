//! Audited Windows primitives for the protected bundled-runtime boundary.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SetFileSecurityW,
};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
};

use crate::NativeHandleError;

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_BYTE: u32 = 0;
const PIPE_READMODE_BYTE: u32 = 0;
const PIPE_WAIT: u32 = 0;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);

/// Parent-side named-pipe endpoint with an inheritable child stdin only.
pub struct ProtectedNamedPipeChannel {
    name: Vec<u16>,
    child_stdin: Option<Stdio>,
}

impl ProtectedNamedPipeChannel {
    /// Creates a fresh owner-scoped endpoint and retains its server handle.
    ///
    /// # Errors
    ///
    /// Returns a closed error when Windows cannot create the owner-scoped pipe.
    pub fn create() -> Result<Self, NativeHandleError> {
        let name = format!("\\\\.\\pipe\\runne-protected-{}", uuid::Uuid::now_v7());
        let wide = wide(&name);
        let descriptor = OwnerSecurityDescriptor::new()?;
        let security = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| NativeHandleError::Unavailable)?,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 1,
        };
        // SAFETY: all pointers refer to NUL-terminated or stack-owned values
        // that remain alive for the synchronous Windows call.
        let server = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                65_536,
                65_536,
                u32::try_from(CHANNEL_TIMEOUT.as_millis())
                    .map_err(|_| NativeHandleError::Unavailable)?,
                &raw const security,
            )
        };
        if server == INVALID_HANDLE_VALUE {
            return Err(NativeHandleError::Unavailable);
        }
        // SAFETY: `server` is a newly-created, exclusively-owned kernel handle.
        let owned = unsafe { OwnedHandle::from_raw_handle(server as RawHandle) };
        Ok(Self {
            name: wide,
            child_stdin: Some(Stdio::from(owned)),
        })
    }

    /// Consumes the endpoint's one inheritable child stdin.
    ///
    /// # Panics
    ///
    /// Panics if called more than once for the same endpoint.
    #[allow(clippy::missing_const_for_fn)]
    pub fn child_stdin(&mut self) -> Stdio {
        self.child_stdin
            .take()
            .expect("protected child stdin is consumed once")
    }

    /// Connects the parent side after the protected child has started.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the child endpoint cannot be connected
    /// within the bounded timeout.
    pub fn connect_parent(&self) -> Result<std::fs::File, NativeHandleError> {
        let deadline = Instant::now() + CHANNEL_TIMEOUT;
        loop {
            // SAFETY: the name is NUL-terminated and all optional pointers are null.
            let handle = unsafe {
                CreateFileW(
                    self.name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                // SAFETY: `handle` is newly-created and transferred exactly once.
                let owned = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
                return Ok(std::fs::File::from(owned));
            }
            // SAFETY: GetLastError has no arguments and is called immediately after failure.
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND {
                return Err(NativeHandleError::Unavailable);
            }
            if Instant::now() >= deadline {
                return Err(NativeHandleError::Unavailable);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let milliseconds = u32::try_from(remaining.as_millis().max(1)).unwrap_or(u32::MAX);
            // SAFETY: the name is NUL-terminated and the timeout is bounded.
            let connected = unsafe { WaitNamedPipeW(self.name.as_ptr(), milliseconds) } != 0;
            if !connected && Instant::now() >= deadline {
                return Err(NativeHandleError::Unavailable);
            }
        }
    }
}

/// Assigns a child to a kill-on-close Job Object owned by the parent.
///
/// # Errors
///
/// Returns a closed error when Windows cannot create, configure, or assign
/// the Job Object.
pub fn assign_kill_on_close_job(child: &Child) -> Result<OwnedHandle, NativeHandleError> {
    // SAFETY: null creates an unnamed job with default security attributes.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() || job == INVALID_HANDLE_VALUE {
        return Err(NativeHandleError::Unavailable);
    }
    // SAFETY: `job` is a newly-created, exclusively-owned kernel handle.
    let owned = unsafe { OwnedHandle::from_raw_handle(job as RawHandle) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the structure pointer and byte length match the documented ABI.
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<std::ffi::c_void>(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| NativeHandleError::Unavailable)?,
        )
    } != 0;
    if !configured {
        return Err(NativeHandleError::Unavailable);
    }
    // SAFETY: the child exposes its owned process handle through the standard API.
    let assigned = unsafe {
        AssignProcessToJobObject(
            job,
            std::os::windows::io::AsRawHandle::as_raw_handle(child).cast(),
        )
    } != 0;
    if !assigned {
        return Err(NativeHandleError::Unavailable);
    }
    Ok(owned)
}

/// Returns the exact client process connected to an inherited named pipe.
///
/// # Errors
///
/// Returns a closed error when the handle is not a connected named pipe.
pub fn named_pipe_peer_process_id(channel: &std::fs::File) -> Result<u32, NativeHandleError> {
    let mut process_id = 0_u32;
    // SAFETY: the file owns a live pipe handle and the output points to one u32.
    let success =
        unsafe { GetNamedPipeClientProcessId(channel.as_raw_handle().cast(), &raw mut process_id) }
            != 0;
    (success && process_id != 0)
        .then_some(process_id)
        .ok_or(NativeHandleError::Unavailable)
}

/// Applies an owner-and-system-only DACL to a mutable protected path.
///
/// # Errors
///
/// Returns a closed error when the path cannot be assigned the required DACL.
pub fn restrict_to_owner(path: &Path) -> Result<(), NativeHandleError> {
    let wide_path = wide(path.as_os_str());
    let descriptor = OwnerSecurityDescriptor::new()?;
    // SAFETY: the path and descriptor remain valid for this synchronous call.
    let result = unsafe {
        SetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    } != 0;
    result.then_some(()).ok_or(NativeHandleError::Unavailable)
}

struct OwnerSecurityDescriptor {
    pointer: *mut std::ffi::c_void,
}

impl OwnerSecurityDescriptor {
    fn new() -> Result<Self, NativeHandleError> {
        let sddl = wide("D:P(A;;FA;;;OW)(A;;FA;;;SY)");
        let mut pointer = std::ptr::null_mut();
        let mut size = 0_u32;
        // SAFETY: the SDDL and output pointers are valid for this call.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &raw mut pointer,
                &raw mut size,
            )
        } != 0;
        if !converted || pointer.is_null() || size == 0 {
            return Err(NativeHandleError::Unavailable);
        }
        Ok(Self { pointer })
    }

    const fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.pointer
    }
}

impl Drop for OwnerSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer was allocated by the matching LocalAlloc family API.
        unsafe {
            LocalFree(self.pointer.cast());
        }
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain([0]).collect()
}
