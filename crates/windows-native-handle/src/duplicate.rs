use std::fmt;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, OpenProcess, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::identity::{DirectoryHandle, NativeHandleError, OwnedHandle};

/// A verified process opened for a single native handle transfer.
pub struct ExactTargetProcess(OwnedHandle);

impl ExactTargetProcess {
    /// Opens the current process instance for duplication and verifies its PID.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the process cannot be opened with exactly the
    /// requested process identifier and duplication rights.
    pub fn open(pid: u32) -> Result<Self, NativeHandleError> {
        (pid != 0)
            .then_some(())
            .ok_or(NativeHandleError::TargetMismatch)?;
        // SAFETY: this requests only duplication/query rights for the supplied PID.
        let handle = unsafe {
            OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        let process = OwnedHandle::new(handle)?;
        // SAFETY: `process` owns a valid process handle.
        (unsafe { GetProcessId(process.raw()) } == pid)
            .then_some(Self(process))
            .ok_or(NativeHandleError::TargetMismatch)
    }

    const fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

impl fmt::Debug for ExactTargetProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactTargetProcess(<redacted>)")
    }
}

/// Owns a duplicate in the exact target process and revokes it on drop.
pub struct RemoteHandleLease {
    target: ExactTargetProcess,
    remote: Option<HANDLE>,
}

impl RemoteHandleLease {
    /// Duplicates a directory only into the pre-verified target process.
    ///
    /// # Errors
    ///
    /// Returns a closed error if Windows cannot create a non-inheritable target
    /// duplicate. The target duplicate is revoked when the lease is dropped.
    pub fn duplicate(
        directory: &DirectoryHandle,
        target: ExactTargetProcess,
    ) -> Result<Self, NativeHandleError> {
        let mut remote = ptr::null_mut();
        // SAFETY: the source is owned locally and the destination process was verified above.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                directory.raw(),
                target.raw(),
                &raw mut remote,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        (ok != 0 && !remote.is_null())
            .then_some(Self {
                target,
                remote: Some(remote),
            })
            .ok_or(NativeHandleError::Unavailable)
    }
}

impl fmt::Debug for RemoteHandleLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteHandleLease(<redacted>)")
    }
}

impl Drop for RemoteHandleLease {
    fn drop(&mut self) {
        let Some(remote) = self.remote.take() else {
            return;
        };
        let mut local_copy = ptr::null_mut();
        // SAFETY: this moves the target-owned duplicate into this process and closes the source.
        let copied = unsafe {
            DuplicateHandle(
                self.target.raw(),
                remote,
                GetCurrentProcess(),
                &raw mut local_copy,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        };
        if copied != 0 && !local_copy.is_null() {
            // SAFETY: `local_copy` is an owned handle produced by DuplicateHandle.
            let _ = unsafe { CloseHandle(local_copy) };
        }
    }
}

pub fn duplicate_local(handle: HANDLE) -> Result<OwnedHandle, NativeHandleError> {
    let mut copy = ptr::null_mut();
    // SAFETY: this duplicates one current-process owned handle with inheritance disabled.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    (ok != 0 && !copy.is_null())
        .then_some(())
        .ok_or(NativeHandleError::Unavailable)?;
    OwnedHandle::new(copy)
}
