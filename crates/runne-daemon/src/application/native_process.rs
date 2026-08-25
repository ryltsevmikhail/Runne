//! Native owner-bound process lifecycle for the protected desktop daemon.
#![allow(dead_code)]

// This adapter is compiled and tested as a qualification artifact while the
// runtime invocation resolver and durable process provider are still being
// composed. It must remain fail-closed and is not advertised as a capability.

use runne_platform_desktop::{NativeProcessFiles, RootHandleBrokerError, VerifiedRootHandle};
use runne_platform_ports::process::{
    HeldFileIdentityV1, ProcessFileKindV1, ProcessPlatformRequestV1, ProcessSymlinkProofV1,
    VerifiedCwdV1, VerifiedExecutableV1,
};
use runne_security::broker::process::{
    OwnedProcessHandleV1, OwnerBoundProcessError, OwnerBoundProcessLaunchRequest,
    OwnerBoundProcessLauncher, ProcessLaunchObservationV1,
};
use std::collections::HashMap;
use std::path::Path;
#[cfg(unix)]
use std::process::Child;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

#[cfg(target_os = "linux")]
#[path = "native_process_linux.rs"]
mod native_linux;
#[cfg(target_os = "macos")]
#[path = "native_process_macos.rs"]
mod native_macos;
#[cfg(target_os = "windows")]
#[path = "native_process_windows.rs"]
mod native_windows;

/// Closed failures while preparing native executable and cwd handles.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum NativeProcessPreparationError {
    #[error("native process material rejected")]
    Rejected,
    #[error("native process material unavailable")]
    Unavailable,
}

struct PreparedProcess {
    files: NativeProcessFiles,
}

struct ActiveProcess {
    #[cfg(unix)]
    child: Option<Child>,
    #[cfg(windows)]
    child: Option<native_windows::WindowsChild>,
    pid: u32,
    start_identity: [u8; 32],
    launch_nonce: [u8; 16],
    output: Arc<Mutex<Vec<CapturedOutput>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturedOutput {
    pub stderr: bool,
    pub bytes: Vec<u8>,
}

/// Native launcher that requires a previously opened executable and cwd.
pub(crate) struct NativeOwnerBoundProcessLauncher {
    root: VerifiedRootHandle,
    prepared: Mutex<HashMap<[u8; 32], PreparedProcess>>,
    active: Mutex<HashMap<u32, ActiveProcess>>,
}

impl NativeOwnerBoundProcessLauncher {
    /// Creates a launcher bound to one already admitted workspace root.
    #[must_use]
    pub(crate) fn new(root: VerifiedRootHandle) -> Self {
        Self {
            root,
            prepared: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Opens and records exact executable/cwd handles for one request digest.
    ///
    /// # Errors
    ///
    /// Returns a closed error when a relative path cannot be opened without
    /// symlink or traversal ambiguity.
    pub(crate) fn prepare(
        &self,
        request_digest: [u8; 32],
        executable: &str,
        cwd: &str,
    ) -> Result<ProcessPlatformRequestV1, NativeProcessPreparationError> {
        if request_digest == [0; 32]
            || self
                .prepared
                .lock()
                .map_err(|_| NativeProcessPreparationError::Unavailable)?
                .contains_key(&request_digest)
        {
            return Err(NativeProcessPreparationError::Rejected);
        }
        let files = self
            .root
            .open_process_files(Path::new(executable), Path::new(cwd))
            .map_err(|error| map_preparation_error(&error))?;
        let executable_identity = HeldFileIdentityV1::new(
            *Uuid::now_v7().as_bytes(),
            files.executable_filesystem_identity_digest(),
            files.executable_content_digest(),
            files.executable_filesystem_identity_digest(),
            1,
        )
        .map_err(|_| NativeProcessPreparationError::Rejected)?;
        let cwd_identity = HeldFileIdentityV1::new(
            *Uuid::now_v7().as_bytes(),
            files.cwd_filesystem_identity_digest(),
            files.cwd_filesystem_identity_digest(),
            files.cwd_filesystem_identity_digest(),
            1,
        )
        .map_err(|_| NativeProcessPreparationError::Rejected)?;
        let executable = VerifiedExecutableV1::new(
            executable_identity,
            ProcessFileKindV1::RegularFile,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .map_err(|_| NativeProcessPreparationError::Rejected)?;
        let cwd = VerifiedCwdV1::new(
            cwd_identity,
            ProcessFileKindV1::Directory,
            ProcessSymlinkProofV1::VerifiedNotSymlink,
        )
        .map_err(|_| NativeProcessPreparationError::Rejected)?;
        let request = ProcessPlatformRequestV1::new(request_digest, executable, cwd)
            .map_err(|_| NativeProcessPreparationError::Rejected)?;
        self.prepared
            .lock()
            .map_err(|_| NativeProcessPreparationError::Unavailable)?
            .insert(request_digest, PreparedProcess { files });
        Ok(request)
    }

    /// Returns captured native output for an active process.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle error when the process is not owned or the
    /// native registry cannot be read.
    pub(crate) fn output(&self, pid: u32) -> Result<Vec<CapturedOutput>, OwnerBoundProcessError> {
        let active = self
            .active
            .lock()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
        let process = active
            .get(&pid)
            .ok_or(OwnerBoundProcessError::OwnershipMismatch)?;
        let output = process
            .output
            .lock()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?
            .clone();
        drop(active);
        Ok(output)
    }

    /// Re-adopts only a still-running process carrying the exact runtime marker.
    pub(crate) fn re_adopt(
        &self,
        handle: OwnedProcessHandleV1,
    ) -> Result<(), OwnerBoundProcessError> {
        re_adopt_process(self, handle)
    }
}

include!("native_process_recovery.rs");

impl OwnerBoundProcessLauncher for NativeOwnerBoundProcessLauncher {
    fn launch(
        &self,
        request: &OwnerBoundProcessLaunchRequest<'_>,
    ) -> Result<ProcessLaunchObservationV1, OwnerBoundProcessError> {
        let prepared = self
            .prepared
            .lock()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?
            .remove(request.prepared().request_digest())
            .ok_or(OwnerBoundProcessError::LifecycleRejected)?;
        if prepared.files.executable_content_digest()
            != *request.prepared().executable().identity().content_digest()
        {
            return Err(OwnerBoundProcessError::LifecycleRejected);
        }
        #[cfg(target_os = "windows")]
        return native_windows::spawn(self, &prepared.files, request);
        #[cfg(target_os = "macos")]
        return native_macos::spawn(self, &prepared.files, request);
        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        {
            let _ = (prepared, request);
            return Err(OwnerBoundProcessError::LifecycleRejected);
        }
        #[cfg(target_os = "linux")]
        native_linux::spawn(self, &prepared.files, request)
    }

    fn stop(&self, handle: &OwnedProcessHandleV1) -> Result<(), OwnerBoundProcessError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?;
        let process = active
            .get_mut(&handle.pid())
            .ok_or(OwnerBoundProcessError::OwnershipMismatch)?;
        if process.start_identity != *handle.start_identity()
            || process.launch_nonce != *handle.launch_nonce()
        {
            return Err(OwnerBoundProcessError::OwnershipMismatch);
        }
        #[cfg(target_os = "linux")]
        native_linux::terminate(process)?;
        #[cfg(target_os = "windows")]
        native_windows::terminate(process)?;
        #[cfg(target_os = "macos")]
        native_macos::terminate(process)?;
        #[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
        return Err(OwnerBoundProcessError::LifecycleRejected);
        active.remove(&handle.pid());
        drop(active);
        Ok(())
    }
}

const fn map_preparation_error(error: &RootHandleBrokerError) -> NativeProcessPreparationError {
    match error {
        RootHandleBrokerError::Rejected => NativeProcessPreparationError::Rejected,
        RootHandleBrokerError::Unavailable => NativeProcessPreparationError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("native_process/tests.rs");
}
