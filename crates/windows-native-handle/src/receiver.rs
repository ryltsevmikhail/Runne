use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::HANDLE;

use crate::duplicate::{LauncherProcessBinding, duplicate_local};
use crate::identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};

const MAX_PENDING_OFFERS: usize = 64;
const MAX_OFFER_MILLIS: u64 = 30_000;
const OFFER_BYTES: usize = 104;
const OFFER_MAGIC: [u8; 4] = *b"GHR1";

pub struct ProtectedHandleOffer {
    bytes: [u8; OFFER_BYTES],
    one_shot: Box<()>,
}
impl ProtectedHandleOffer {
    pub(crate) fn transcript(&self) -> [u8; 32] {
        self.bytes[72..104].try_into().unwrap()
    }
    #[must_use]
    pub fn into_protected_bytes(self) -> [u8; OFFER_BYTES] {
        self.bytes
    }

    /// # Errors
    /// Rejects malformed protected-channel data.
    pub fn from_protected_bytes(bytes: [u8; OFFER_BYTES]) -> Result<Self, NativeHandleError> {
        ReceivedHandleOffer::decode(bytes).map(|_| Self {
            bytes,
            one_shot: Box::new(()),
        })
    }
}
impl fmt::Debug for ProtectedHandleOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedHandleOffer(<redacted>)")
    }
}
pub struct ReceivedHandleOffer {
    offer_id: [u8; 16],
    binding: LauncherProcessBinding,
    expected_identity: DirectoryIdentity,
    borrowed_remote: HANDLE,
    deadline_millis: u64,
    transcript: [u8; 32],
    one_shot: Box<()>,
}
impl ReceivedHandleOffer {
    pub(crate) fn new(
        offer_id: [u8; 16],
        binding: LauncherProcessBinding,
        expected_identity: DirectoryIdentity,
        borrowed_remote: HANDLE,
        deadline_millis: u64,
        now_millis: u64,
    ) -> Result<Self, NativeHandleError> {
        if offer_id == [0; 16]
            || borrowed_remote.is_null()
            || deadline_millis <= now_millis
            || deadline_millis.saturating_sub(now_millis) > MAX_OFFER_MILLIS
        {
            return Err(NativeHandleError::Rejected);
        }
        Ok(Self {
            offer_id,
            binding,
            expected_identity,
            borrowed_remote,
            deadline_millis,
            transcript: [0; 32],
            one_shot: Box::new(()),
        })
    }

    pub(crate) fn encode(self) -> ProtectedHandleOffer {
        let (volume_serial, file_id) = self.expected_identity.wire_parts();
        let mut bytes = [0; OFFER_BYTES];
        bytes[..4].copy_from_slice(&OFFER_MAGIC);
        bytes[4..20].copy_from_slice(&self.offer_id);
        bytes[20..24].copy_from_slice(&self.binding.expected_pid().to_be_bytes());
        bytes[24..32].copy_from_slice(&self.binding.launch_generation().to_be_bytes());
        bytes[32..40].copy_from_slice(&volume_serial.to_be_bytes());
        bytes[40..56].copy_from_slice(&file_id);
        bytes[56..64].copy_from_slice(&self.deadline_millis.to_be_bytes());
        bytes[64..72].copy_from_slice(&(self.borrowed_remote as usize as u64).to_be_bytes());
        let transcript = transcript(&bytes[..72]);
        bytes[72..104].copy_from_slice(&transcript);
        ProtectedHandleOffer {
            bytes,
            one_shot: Box::new(()),
        }
    }

    fn decode(bytes: [u8; OFFER_BYTES]) -> Result<Self, NativeHandleError> {
        if bytes[..4] != OFFER_MAGIC {
            return Err(NativeHandleError::Rejected);
        }
        let mut offer_id = [0; 16];
        offer_id.copy_from_slice(&bytes[4..20]);
        let binding = LauncherProcessBinding::new(
            u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        )?;
        let identity = DirectoryIdentity::from_wire(
            u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            bytes[40..56].try_into().unwrap(),
        )?;
        let deadline_millis = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
        if bytes[72..104] != transcript(&bytes[..72]) {
            return Err(NativeHandleError::Rejected);
        }
        let raw = usize::try_from(u64::from_be_bytes(bytes[64..72].try_into().unwrap()))
            .map_err(|_| NativeHandleError::Rejected)? as HANDLE;
        let mut offer = Self::new(offer_id, binding, identity, raw, deadline_millis, 0)?;
        offer.transcript.copy_from_slice(&bytes[72..104]);
        Ok(offer)
    }
}
impl fmt::Debug for ReceivedHandleOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivedHandleOffer(<redacted>)")
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HandleOfferAck {
    offer_id: [u8; 16],
    transcript: [u8; 32],
}
impl HandleOfferAck {
    pub(crate) fn matches(self, offer_id: [u8; 16], transcript: [u8; 32]) -> bool {
        self.offer_id == offer_id && self.transcript == transcript
    }
}
impl fmt::Debug for HandleOfferAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandleOfferAck(<redacted>)")
    }
}
pub struct AcceptedDirectory {
    directory: DirectoryHandle,
    ack: HandleOfferAck,
}
impl AcceptedDirectory {
    #[must_use]
    pub fn into_directory(self) -> DirectoryHandle {
        self.directory
    }

    #[must_use]
    pub const fn ack(&self) -> HandleOfferAck {
        self.ack
    }
}
impl fmt::Debug for AcceptedDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedDirectory(<redacted>)")
    }
}
pub enum ReceiverDisposition {
    Ack(AcceptedDirectory),
    Nack,
    Expired,
}
impl fmt::Debug for ReceiverDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiverDisposition(<redacted>)")
    }
}
pub struct StagedHandleReceiver {
    binding: LauncherProcessBinding,
    capacity: usize,
    pending: BTreeMap<[u8; 16], PendingOffer>,
    completed: BTreeMap<[u8; 16], u64>,
}
struct PendingOffer {
    borrowed_remote: HANDLE,
    expected_identity: DirectoryIdentity,
    deadline_millis: u64,
    transcript: [u8; 32],
}
impl StagedHandleReceiver {
    /// # Errors
    /// Rejects a non-current target binding or invalid capacity.
    pub fn new(
        binding: LauncherProcessBinding,
        capacity: usize,
    ) -> Result<Self, NativeHandleError> {
        if binding.expected_pid() != std::process::id()
            || capacity == 0
            || capacity > MAX_PENDING_OFFERS
        {
            return Err(NativeHandleError::TargetMismatch);
        }
        Ok(Self {
            binding,
            capacity,
            pending: BTreeMap::new(),
            completed: BTreeMap::new(),
        })
    }

    /// # Errors
    /// Rejects expired, replayed, mismatched, or over-capacity offers.
    pub fn stage(
        &mut self,
        offer: ProtectedHandleOffer,
        now_millis: u64,
    ) -> Result<(), NativeHandleError> {
        let ProtectedHandleOffer {
            bytes,
            one_shot: _offer_guard,
        } = offer;
        let ReceivedHandleOffer {
            offer_id,
            binding,
            expected_identity,
            borrowed_remote,
            deadline_millis,
            transcript,
            one_shot: _one_shot,
        } = ReceivedHandleOffer::decode(bytes)?;
        self.purge_expired(now_millis);
        if binding != self.binding
            || self.pending.len() >= self.capacity
            || self.pending.contains_key(&offer_id)
            || self.completed.contains_key(&offer_id)
        {
            return Err(NativeHandleError::Rejected);
        }
        if deadline_millis <= now_millis {
            return Err(NativeHandleError::Rejected);
        }
        self.pending.insert(
            offer_id,
            PendingOffer {
                borrowed_remote,
                expected_identity,
                deadline_millis,
                transcript,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn clone_received_and_verify(
        &mut self,
        offer_id: [u8; 16],
        now_millis: u64,
    ) -> ReceiverDisposition {
        let Some(received) = self.pending.remove(&offer_id) else {
            return ReceiverDisposition::Nack;
        };
        if now_millis >= received.deadline_millis {
            self.completed.insert(offer_id, received.deadline_millis);
            return ReceiverDisposition::Expired;
        }
        let result = duplicate_local(received.borrowed_remote).and_then(|owned| {
            let directory = DirectoryHandle::from_owned(owned)?;
            (directory.identity() == received.expected_identity)
                .then_some(directory)
                .ok_or(NativeHandleError::Rejected)
        });
        self.completed.insert(offer_id, received.deadline_millis);
        result.map_or_else(
            |_| ReceiverDisposition::Nack,
            |directory| {
                ReceiverDisposition::Ack(AcceptedDirectory {
                    directory,
                    ack: HandleOfferAck {
                        offer_id,
                        transcript: received.transcript,
                    },
                })
            },
        )
    }

    fn purge_expired(&mut self, now_millis: u64) {
        self.pending
            .retain(|_, offer| offer.deadline_millis > now_millis);
        self.completed.retain(|_, deadline| *deadline > now_millis);
    }
}

fn transcript(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.root-handle-offer.v1");
    hasher.update(bytes);
    hasher.finalize().into()
}

impl fmt::Debug for StagedHandleReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagedHandleReceiver(<redacted>)")
    }
}
