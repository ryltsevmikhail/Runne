use std::collections::BTreeMap;
use std::fmt;

use windows_sys::Win32::Foundation::HANDLE;

use crate::clock::{ClockSample, ProtocolClock};
use crate::duplicate::{LauncherProcessBinding, duplicate_local};
use crate::identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};
use crate::model::{ControlAction, OfferAction, ReceiverModel, TargetBinding};
use crate::wire::{ControlKind, HandleFinalize, HandleNack, ProtectedHandleOffer};
use crate::{HandleAckReady, ProtocolError};

/// Verified directory made available only after the sender has successfully
/// revoked its target-side original and sent an exact finalization frame.
pub struct CommittedDirectory(DirectoryHandle);

impl CommittedDirectory {
    #[must_use]
    pub fn into_directory(self) -> DirectoryHandle {
        self.0
    }
}

impl fmt::Debug for CommittedDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedDirectory(<redacted>)")
    }
}

/// One protected receiver reaction. A ready acknowledgement does not release
/// a directory; only a subsequent exact `Finalize` can do so.
pub enum ReceiverDisposition {
    AckReady(HandleAckReady),
    Finalize(HandleFinalize),
    Nack(HandleNack),
    Committed(CommittedDirectory),
}

impl fmt::Debug for ReceiverDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiverDisposition(<redacted>)")
    }
}

/// Bounded receiver state for one exact protected daemon child.
pub struct StagedHandleReceiver {
    model: ReceiverModel,
    clock: ProtocolClock,
    ready: BTreeMap<[u8; 16], DirectoryHandle>,
}

impl StagedHandleReceiver {
    /// # Errors
    ///
    /// Rejects a binding that is not this protected child.
    pub fn new(binding: LauncherProcessBinding) -> Result<Self, NativeHandleError> {
        if binding.expected_pid() != std::process::id() {
            return Err(NativeHandleError::TargetMismatch);
        }
        let model = ReceiverModel::new(
            TargetBinding::new(binding.expected_pid(), binding.launch_generation())
                .map_err(map_protocol)?,
        );
        Ok(Self {
            model,
            clock: ProtocolClock::default(),
            ready: BTreeMap::new(),
        })
    }

    /// Stages an offer, clones and re-verifies it, then emits only `AckReady`.
    /// The verified clone stays owned by this receiver until terminal handling.
    ///
    /// # Errors
    ///
    /// Rejects an invalid clock sample, protected frame, or local clone.
    pub fn receive_offer(
        &mut self,
        offer: &ProtectedHandleOffer,
        sample: ClockSample,
    ) -> Result<ReceiverDisposition, NativeHandleError> {
        let now = self.clock.observe(sample).map_err(map_protocol)?;
        self.drop_expired(now);
        match self.model.begin(offer, now).map_err(map_protocol)? {
            OfferAction::Ready(ready) => Ok(ReceiverDisposition::AckReady(ready)),
            OfferAction::Nack(nack) => Ok(ReceiverDisposition::Nack(nack)),
            OfferAction::Clone(parts) => self.clone_then_ready(parts, now),
        }
    }

    /// Processes exactly one sender `Finalize` or `Nack` frame. A replay never
    /// clones or commits another directory.
    ///
    /// # Errors
    ///
    /// Rejects malformed frames, clock failures, and a terminal cancellation.
    pub fn receive_control(
        &mut self,
        bytes: [u8; crate::wire::CONTROL_BYTES],
        sample: ClockSample,
    ) -> Result<ReceiverDisposition, NativeHandleError> {
        let now = self.clock.observe(sample).map_err(map_protocol)?;
        self.drop_expired(now);
        let control = crate::wire::decode_control_for_receiver(bytes).map_err(map_protocol)?;
        if control.kind == ControlKind::Ready {
            return Ok(ReceiverDisposition::Nack(crate::wire::nack_from_control(
                control,
            )));
        }
        match self.model.control(control, now) {
            ControlAction::Commit(id) => self
                .ready
                .remove(&id)
                .map(|directory| ReceiverDisposition::Committed(CommittedDirectory(directory)))
                .ok_or(NativeHandleError::Rejected),
            ControlAction::Drop(id) => {
                self.ready.remove(&id);
                self.model
                    .cancel(id)
                    .map(ReceiverDisposition::Nack)
                    .ok_or(NativeHandleError::Rejected)
            }
            ControlAction::Finalize(frame) => Ok(ReceiverDisposition::Finalize(frame)),
            ControlAction::Nack(frame) => Ok(ReceiverDisposition::Nack(frame)),
        }
    }

    /// Cancels one staged/ready offer and drops its clone.
    pub fn cancel(&mut self, offer_id: [u8; 16]) -> Option<HandleNack> {
        self.ready.remove(&offer_id);
        self.model.cancel(offer_id)
    }

    /// Fences channel loss: all locally cloned directories are dropped and no
    /// later frame can obtain them.
    pub fn close(&mut self) {
        for id in self.model.close() {
            self.ready.remove(&id);
        }
    }

    fn clone_then_ready(
        &mut self,
        parts: crate::wire::OfferParts,
        now: u64,
    ) -> Result<ReceiverDisposition, NativeHandleError> {
        let remote = remote_handle(parts.remote_token)?;
        let directory = duplicate_local(remote).and_then(DirectoryHandle::from_owned);
        let Ok(directory) = directory else {
            return Ok(ReceiverDisposition::Nack(self.model.reject(parts)));
        };
        if directory.identity() != identity(parts.identity) {
            return Ok(ReceiverDisposition::Nack(self.model.reject(parts)));
        }
        let ready = self.model.ready(parts, now).map_err(map_protocol)?;
        self.ready.insert(parts.offer_id, directory);
        Ok(ReceiverDisposition::AckReady(ready))
    }

    fn drop_expired(&mut self, now: u64) {
        for id in self.model.expire(now) {
            self.ready.remove(&id);
        }
    }
}

impl Drop for StagedHandleReceiver {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for StagedHandleReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagedHandleReceiver(<redacted>)")
    }
}

fn remote_handle(token: u64) -> Result<HANDLE, NativeHandleError> {
    let raw = usize::try_from(token).map_err(|_| NativeHandleError::Rejected)?;
    let handle = raw as HANDLE;
    (!handle.is_null())
        .then_some(handle)
        .ok_or(NativeHandleError::Rejected)
}

fn identity(value: crate::wire::IdentityWire) -> DirectoryIdentity {
    DirectoryIdentity::from_wire(value.volume_serial, value.file_id)
        .expect("structurally checked wire identity")
}

const fn map_protocol(_: ProtocolError) -> NativeHandleError {
    NativeHandleError::Rejected
}
