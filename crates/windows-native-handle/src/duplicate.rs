use std::fmt;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId};

use crate::identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError, OwnedHandle};
use crate::receiver::{HandleOfferAck, ProtectedHandleOffer, ReceivedHandleOffer};

/// Non-reusable launcher facts bound into one protected child transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LauncherProcessBinding {
    expected_pid: u32,
    launch_generation: u64,
}

impl LauncherProcessBinding {
    /// Creates a bounded binding from launcher-owned child facts.
    ///
    /// # Errors
    ///
    /// Returns a closed error for zero PID or launch generation.
    pub const fn new(expected_pid: u32, launch_generation: u64) -> Result<Self, NativeHandleError> {
        if expected_pid == 0 || launch_generation == 0 {
            return Err(NativeHandleError::TargetMismatch);
        }
        Ok(Self {
            expected_pid,
            launch_generation,
        })
    }

    pub(crate) const fn expected_pid(self) -> u32 {
        self.expected_pid
    }

    pub(crate) const fn launch_generation(self) -> u64 {
        self.launch_generation
    }
}

/// A duplicated, exact process instance that originated from the launcher child.
pub struct ExactTargetProcess {
    process: OwnedHandle,
    binding: LauncherProcessBinding,
}

impl ExactTargetProcess {
    /// Duplicates a launcher-owned child handle and binds it to launch facts.
    ///
    /// # Errors
    ///
    /// Returns a closed error if `child` is not the expected live child or its
    /// owned handle cannot be duplicated with the required identity.
    pub fn from_launcher_child(
        child: &Child,
        binding: LauncherProcessBinding,
    ) -> Result<Self, NativeHandleError> {
        if child.id() != binding.expected_pid {
            return Err(NativeHandleError::TargetMismatch);
        }
        let mut owned = ptr::null_mut();
        // SAFETY: `child` owns this current-process handle for the call duration.
        let copied = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.as_raw_handle().cast(),
                GetCurrentProcess(),
                &raw mut owned,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        (copied != 0 && !owned.is_null())
            .then_some(())
            .ok_or(NativeHandleError::Unavailable)?;
        let process = OwnedHandle::new(owned)?;
        // SAFETY: `process` is the owned duplicate of the launcher child handle.
        (unsafe { GetProcessId(process.raw()) } == binding.expected_pid)
            .then_some(Self { process, binding })
            .ok_or(NativeHandleError::TargetMismatch)
    }

    const fn raw(&self) -> HANDLE {
        self.process.raw()
    }
}

impl fmt::Debug for ExactTargetProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactTargetProcess(<redacted>)")
    }
}

/// Owns a target duplicate until an authenticated ACK or bounded cleanup.
pub struct RemoteHandleLease {
    target: ExactTargetProcess,
    identity: DirectoryIdentity,
    remote: Option<HANDLE>,
    issued_offer: Option<[u8; 16]>,
}

impl RemoteHandleLease {
    /// Duplicates a directory only into the exact launcher-owned target process.
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
        // SAFETY: source ownership and the duplicated target process are both verified.
        let copied = unsafe {
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
        (copied != 0 && !remote.is_null())
            .then_some(Self {
                target,
                identity: directory.identity(),
                remote: Some(remote),
                issued_offer: None,
            })
            .ok_or(NativeHandleError::Unavailable)
    }

    /// Creates one opaque offer for an already-authenticated protected channel.
    ///
    /// # Errors
    ///
    /// Returns a closed error for reused identifiers, empty IDs, or TTL outside
    /// the receiver's bounded acceptance window.
    pub fn issue_offer(
        &mut self,
        offer_id: [u8; 16],
        ttl: Duration,
    ) -> Result<ProtectedHandleOffer, NativeHandleError> {
        if offer_id == [0; 16] || self.issued_offer.is_some() {
            return Err(NativeHandleError::Rejected);
        }
        let remote = self.remote.ok_or(NativeHandleError::Unavailable)?;
        let offer =
            ReceivedHandleOffer::new(offer_id, self.target.binding, self.identity, remote, ttl)?
                .encode()?;
        self.issued_offer = Some(offer_id);
        Ok(offer)
    }

    /// Verifies a receiver ACK and immediately revokes the target-side original.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an ACK that does not match this one-shot lease
    /// or when Windows cannot complete source-side revocation. Missing ACKs are
    /// revoked by `Drop` when the bounded source operation ends.
    pub fn acknowledge(mut self, ack: HandleOfferAck) -> Result<(), NativeHandleError> {
        match self.issued_offer {
            Some(offer_id) if ack.matches(offer_id) => self.revoke(),
            _ => Err(NativeHandleError::Rejected),
        }
    }

    fn revoke(&mut self) -> Result<(), NativeHandleError> {
        let remote = self.remote.ok_or(NativeHandleError::Unavailable)?;
        let mut local_copy = ptr::null_mut();
        // SAFETY: this revokes the target duplicate and produces only a temporary local copy.
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
        if copied == 0 || local_copy.is_null() {
            return Err(NativeHandleError::Unavailable);
        }
        self.remote = None;
        // SAFETY: `local_copy` is owned locally after revoking the remote original.
        let _ = unsafe { CloseHandle(local_copy) };
        Ok(())
    }
}

impl fmt::Debug for RemoteHandleLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteHandleLease(<redacted>)")
    }
}

impl Drop for RemoteHandleLease {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

pub fn duplicate_local(handle: HANDLE) -> Result<OwnedHandle, NativeHandleError> {
    let mut copy = ptr::null_mut();
    // SAFETY: this clones but never adopts or closes the borrowed current-process value.
    let copied = unsafe {
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
    (copied != 0 && !copy.is_null())
        .then_some(())
        .ok_or(NativeHandleError::Unavailable)?;
    OwnedHandle::new(copy)
}
