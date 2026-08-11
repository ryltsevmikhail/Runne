use std::fmt;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId};

use crate::ProtocolError;
use crate::clock::{ClockSample, ProtocolClock};
use crate::identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError, OwnedHandle};
use crate::model::TargetBinding;
use crate::wire::{self, HandleAckReady, HandleFinalize, ProtectedHandleOffer};

/// Non-reusable launcher facts bound into one protected child transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LauncherProcessBinding(TargetBinding);

impl LauncherProcessBinding {
    /// Creates a binding from launcher-owned child facts.
    ///
    /// # Errors
    ///
    /// Rejects zero process IDs or launch generations.
    pub fn new(expected_pid: u32, launch_generation: u64) -> Result<Self, NativeHandleError> {
        TargetBinding::new(expected_pid, launch_generation)
            .map(Self)
            .map_err(map_protocol)
    }

    pub(crate) const fn expected_pid(self) -> u32 {
        self.0.pid
    }

    pub(crate) const fn launch_generation(self) -> u64 {
        self.0.launch_generation
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
    /// Rejects a child that does not match its exact launcher binding.
    pub fn from_launcher_child(
        child: &Child,
        binding: LauncherProcessBinding,
    ) -> Result<Self, NativeHandleError> {
        if child.id() != binding.expected_pid() {
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
        (unsafe { GetProcessId(process.raw()) } == binding.expected_pid())
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

/// A target duplicate before it is bound to one protected offer.
pub struct RemoteHandleLease {
    target: Option<ExactTargetProcess>,
    identity: DirectoryIdentity,
    remote: Option<HANDLE>,
}

impl RemoteHandleLease {
    /// Duplicates a directory only into the exact launcher-owned target process.
    ///
    /// # Errors
    ///
    /// Returns a closed error when Windows cannot create a target duplicate.
    pub fn duplicate(
        directory: &DirectoryHandle,
        target: ExactTargetProcess,
    ) -> Result<Self, NativeHandleError> {
        let mut remote = ptr::null_mut();
        // SAFETY: source ownership and target process identity are both verified.
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
                target: Some(target),
                identity: directory.identity(),
                remote: Some(remote),
            })
            .ok_or(NativeHandleError::Unavailable)
    }

    /// Consumes this lease into a one-offer typestate. The absolute deadline is
    /// computed from an injected clock and cannot exceed 30 seconds.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid offer ID, deadline, clock sample,
    /// or a missing target duplicate.
    pub fn offer(
        mut self,
        offer_id: [u8; 16],
        ttl_millis: u64,
        sample: ClockSample,
    ) -> Result<(OfferedRemoteHandleLease, ProtectedHandleOffer), NativeHandleError> {
        if offer_id == [0; 16] {
            return Err(NativeHandleError::Rejected);
        }
        let mut clock = ProtocolClock::default();
        let deadline = clock.deadline(sample, ttl_millis).map_err(map_protocol)?;
        let remote = self.remote.take().ok_or(NativeHandleError::Unavailable)?;
        let target = self.target.take().ok_or(NativeHandleError::Unavailable)?;
        let (volume_serial, file_id) = self.identity.wire_parts();
        let offer = wire::encode_offer(wire::OfferParts {
            offer_id,
            target_pid: target.binding.expected_pid(),
            launch_generation: target.binding.launch_generation(),
            identity: wire::IdentityWire {
                volume_serial,
                file_id,
            },
            deadline_millis: deadline,
            remote_token: remote as usize as u64,
            transcript: [0; 32],
        });
        let parts = offer.parts().map_err(map_protocol)?;
        Ok((
            OfferedRemoteHandleLease {
                target,
                remote: Some(remote),
                parts,
                clock,
            },
            offer,
        ))
    }
}

impl Drop for RemoteHandleLease {
    fn drop(&mut self) {
        if let Some(target) = self.target.as_ref() {
            revoke_once(target, self.remote.take());
        }
    }
}

impl fmt::Debug for RemoteHandleLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteHandleLease(<redacted>)")
    }
}

/// A lease after one exact `GHO2` offer was emitted. It can accept only its
/// matching `GHA2`; success revokes the target original before producing GHF2.
pub struct OfferedRemoteHandleLease {
    target: ExactTargetProcess,
    remote: Option<HANDLE>,
    parts: wire::OfferParts,
    clock: ProtocolClock,
}

impl OfferedRemoteHandleLease {
    /// Validates a ready acknowledgement and revokes the remote source exactly
    /// once before returning a finalization frame.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a mismatched/expired acknowledgement or an
    /// ambiguous Windows source revocation. It never emits `Finalize` then.
    pub fn acknowledge_ready(
        mut self,
        ready: &HandleAckReady,
        sample: ClockSample,
    ) -> Result<HandleFinalize, NativeHandleError> {
        let now = self.clock.observe(sample).map_err(map_protocol)?;
        let control = ready.parts().map_err(map_protocol)?;
        if control.kind != wire::ControlKind::Ready
            || control.offer_id != self.parts.offer_id
            || control.transcript != self.parts.transcript
            || now >= self.parts.deadline_millis
        {
            return Err(NativeHandleError::Rejected);
        }
        let remote = self.remote.take().ok_or(NativeHandleError::Unavailable)?;
        revoke_taken(&self.target, remote)?;
        Ok(wire::finalize(self.parts))
    }

    /// Aborts this offer. Drop performs the one-shot target-side cleanup.
    pub fn abort(self) {}
}

impl Drop for OfferedRemoteHandleLease {
    fn drop(&mut self) {
        revoke_once(&self.target, self.remote.take());
    }
}

impl fmt::Debug for OfferedRemoteHandleLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OfferedRemoteHandleLease(<redacted>)")
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(super) fn duplicate_local(handle: HANDLE) -> Result<OwnedHandle, NativeHandleError> {
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

fn revoke_once(target: &ExactTargetProcess, remote: Option<HANDLE>) {
    if let Some(remote) = remote {
        let _ = revoke_taken(target, remote);
    }
}

fn revoke_taken(target: &ExactTargetProcess, remote: HANDLE) -> Result<(), NativeHandleError> {
    let mut local_copy = ptr::null_mut();
    // SAFETY: the remote value is disarmed before this call and is never retried.
    let copied = unsafe {
        DuplicateHandle(
            target.raw(),
            remote,
            GetCurrentProcess(),
            &raw mut local_copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        )
    };
    if !local_copy.is_null() {
        // SAFETY: a successful or ambiguous duplication returned a local owned copy.
        let _ = unsafe { CloseHandle(local_copy) };
    }
    (copied != 0)
        .then_some(())
        .ok_or(NativeHandleError::Unavailable)
}

const fn map_protocol(_: ProtocolError) -> NativeHandleError {
    NativeHandleError::Rejected
}
