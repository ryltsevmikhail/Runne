//! Native Windows handle transfer over the already-authenticated pipe.

use std::fs::File;
use std::io::{Read, Write};
use std::process::Child;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::{
    ClockSample, DirectoryHandle, ExactTargetProcess, HandleAckReady, LauncherProcessBinding,
    NativeHandleError, ProtectedHandleOffer, ReceiverDisposition, RemoteHandleLease,
    StagedHandleReceiver,
};

const OFFER_BYTES: usize = 104;
const CONTROL_BYTES: usize = 64;
const TRANSFER_TTL_MILLIS: u64 = 30_000;

/// One-shot sender bound to the exact protected daemon process.
pub struct ProtectedHandleSender {
    target: Option<ExactTargetProcess>,
}

impl ProtectedHandleSender {
    /// Binds the sender to the process handle owned by the launcher.
    ///
    /// # Errors
    ///
    /// Rejects a process whose PID does not match the launch binding.
    pub fn from_child(child: &Child, launch_generation: u64) -> Result<Self, NativeHandleError> {
        let binding = LauncherProcessBinding::new(child.id(), launch_generation)?;
        Ok(Self {
            target: Some(ExactTargetProcess::from_launcher_child(child, binding)?),
        })
    }

    /// Duplicates one directory into the exact child and commits it once.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the offer, acknowledgement, revocation, or
    /// finalization frame is invalid.
    pub fn send(
        &mut self,
        channel: &mut File,
        directory: &DirectoryHandle,
        offer_id: [u8; 16],
    ) -> Result<(), NativeHandleError> {
        let target = self.target.take().ok_or(NativeHandleError::Rejected)?;
        let lease = RemoteHandleLease::duplicate(directory, target)?;
        let (offered, offer) = lease.offer(offer_id, TRANSFER_TTL_MILLIS, sample()?)?;
        write_frame(channel, &offer.into_protected_bytes())?;
        let mut ready_bytes = [0; CONTROL_BYTES];
        channel
            .read_exact(&mut ready_bytes)
            .map_err(|_| NativeHandleError::Unavailable)?;
        let ready = HandleAckReady::from_protected_bytes(ready_bytes)
            .map_err(|_| NativeHandleError::Rejected)?;
        let finalize = offered.acknowledge_ready(&ready, sample()?)?;
        write_frame(channel, &finalize.into_protected_bytes())
    }
}

/// Receiver that keeps staged handles private until exact finalization.
pub struct ProtectedHandleReceiver {
    receiver: StagedHandleReceiver,
}

impl ProtectedHandleReceiver {
    /// Binds the receiver to the current protected daemon process.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid launch generation.
    pub fn new(launch_generation: u64) -> Result<Self, NativeHandleError> {
        let binding = LauncherProcessBinding::new(std::process::id(), launch_generation)?;
        Ok(Self {
            receiver: StagedHandleReceiver::new(binding)?,
        })
    }

    /// Receives and commits one handle whose ID is bound to the signed offer.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a malformed offer, an identity mismatch, a
    /// replay, or a missing finalization.
    pub fn receive(
        &mut self,
        channel: &mut File,
        expected_offer_id: [u8; 16],
    ) -> Result<DirectoryHandle, NativeHandleError> {
        let mut offer_bytes = [0; OFFER_BYTES];
        channel
            .read_exact(&mut offer_bytes)
            .map_err(|_| NativeHandleError::Unavailable)?;
        if expected_offer_id == [0; 16] || offer_bytes[4..20] != expected_offer_id {
            return Err(NativeHandleError::Rejected);
        }
        let offer = ProtectedHandleOffer::from_protected_bytes(offer_bytes)
            .map_err(|_| NativeHandleError::Rejected)?;
        let disposition = self.receiver.receive_offer(&offer, sample()?)?;
        match disposition {
            ReceiverDisposition::AckReady(ready) => {
                write_frame(channel, &ready.into_protected_bytes())?;
                let mut control_bytes = [0; CONTROL_BYTES];
                channel
                    .read_exact(&mut control_bytes)
                    .map_err(|_| NativeHandleError::Unavailable)?;
                let disposition = self.receiver.receive_control(control_bytes, sample()?)?;
                match disposition {
                    ReceiverDisposition::Committed(directory) => Ok(directory.into_directory()),
                    ReceiverDisposition::Nack(nack) => {
                        let _ = write_frame(channel, &nack.into_protected_bytes());
                        Err(NativeHandleError::Rejected)
                    }
                    ReceiverDisposition::Finalize(_) | ReceiverDisposition::AckReady(_) => {
                        Err(NativeHandleError::Rejected)
                    }
                }
            }
            ReceiverDisposition::Nack(nack) => {
                write_frame(channel, &nack.into_protected_bytes())?;
                Err(NativeHandleError::Rejected)
            }
            ReceiverDisposition::Committed(_) | ReceiverDisposition::Finalize(_) => {
                Err(NativeHandleError::Rejected)
            }
        }
    }
}

fn write_frame(channel: &mut File, bytes: &[u8]) -> Result<(), NativeHandleError> {
    if bytes.len() != CONTROL_BYTES && bytes.len() != OFFER_BYTES {
        return Err(NativeHandleError::Rejected);
    }
    channel
        .write_all(bytes)
        .and_then(|()| channel.flush())
        .map_err(|_| NativeHandleError::Unavailable)
}

fn sample() -> Result<ClockSample, NativeHandleError> {
    let wall_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NativeHandleError::Unavailable)?
        .as_millis();
    let wall_millis = u64::try_from(wall_millis).map_err(|_| NativeHandleError::Unavailable)?;
    let origin = MONOTONIC_ORIGIN.get_or_init(Instant::now);
    let monotonic_millis =
        u64::try_from(origin.elapsed().as_millis()).map_err(|_| NativeHandleError::Unavailable)?;
    Ok(ClockSample {
        wall_millis,
        monotonic_millis,
    })
}

static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();
