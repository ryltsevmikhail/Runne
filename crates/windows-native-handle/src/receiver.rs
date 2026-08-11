use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;

use crate::duplicate::{LauncherProcessBinding, duplicate_local};
use crate::identity::{DirectoryHandle, DirectoryIdentity, NativeHandleError};

const MAX_PENDING_OFFERS: usize = 64;
const MAX_OFFER_TTL: Duration = Duration::from_secs(30);
const OFFER_BYTES: usize = 68;
const OFFER_MAGIC: [u8; 4] = *b"GHR1";

pub struct ProtectedHandleOffer {
    bytes: [u8; OFFER_BYTES],
    one_shot: Box<()>,
}

impl ProtectedHandleOffer {
    /// Returns bytes only for the launcher-owned authenticated protected channel.
    #[must_use]
    pub fn into_protected_bytes(self) -> [u8; OFFER_BYTES] {
        self.bytes
    }

    /// Decodes bytes received from the authenticated protected channel.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, unsupported, or out-of-policy data.
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
    ttl: Duration,
    one_shot: Box<()>,
}

impl ReceivedHandleOffer {
    pub(crate) fn new(
        offer_id: [u8; 16],
        binding: LauncherProcessBinding,
        expected_identity: DirectoryIdentity,
        borrowed_remote: HANDLE,
        ttl: Duration,
    ) -> Result<Self, NativeHandleError> {
        if offer_id == [0; 16] || borrowed_remote.is_null() || ttl.is_zero() || ttl > MAX_OFFER_TTL
        {
            return Err(NativeHandleError::Rejected);
        }
        Ok(Self {
            offer_id,
            binding,
            expected_identity,
            borrowed_remote,
            ttl,
            one_shot: Box::new(()),
        })
    }

    pub(crate) fn encode(self) -> Result<ProtectedHandleOffer, NativeHandleError> {
        let ttl_millis =
            u32::try_from(self.ttl.as_millis()).map_err(|_| NativeHandleError::Rejected)?;
        let (volume_serial, file_id) = self.expected_identity.wire_parts();
        let mut bytes = [0; OFFER_BYTES];
        bytes[..4].copy_from_slice(&OFFER_MAGIC);
        bytes[4..20].copy_from_slice(&self.offer_id);
        bytes[20..24].copy_from_slice(&self.binding.expected_pid().to_be_bytes());
        bytes[24..32].copy_from_slice(&self.binding.launch_generation().to_be_bytes());
        bytes[32..40].copy_from_slice(&volume_serial.to_be_bytes());
        bytes[40..56].copy_from_slice(&file_id);
        bytes[56..60].copy_from_slice(&ttl_millis.to_be_bytes());
        bytes[60..68].copy_from_slice(&(self.borrowed_remote as usize as u64).to_be_bytes());
        Ok(ProtectedHandleOffer {
            bytes,
            one_shot: Box::new(()),
        })
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
        let ttl = Duration::from_millis(u64::from(u32::from_be_bytes(
            bytes[56..60].try_into().unwrap(),
        )));
        let raw = usize::try_from(u64::from_be_bytes(bytes[60..68].try_into().unwrap()))
            .map_err(|_| NativeHandleError::Rejected)? as HANDLE;
        Self::new(offer_id, binding, identity, raw, ttl)
    }
}

impl fmt::Debug for ReceivedHandleOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivedHandleOffer(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HandleOfferAck([u8; 16]);

impl HandleOfferAck {
    pub(crate) fn matches(self, offer_id: [u8; 16]) -> bool {
        self.0 == offer_id
    }
}

impl fmt::Debug for HandleOfferAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandleOfferAck(<redacted>)")
    }
}

/// The verified local clone and its ACK. It never exposes the borrowed value.
pub struct AcceptedDirectory {
    directory: DirectoryHandle,
    ack: HandleOfferAck,
}

impl AcceptedDirectory {
    /// Returns the verified local clone after the one-shot receiver acceptance.
    #[must_use]
    pub fn into_directory(self) -> DirectoryHandle {
        self.directory
    }

    /// Returns the opaque ACK for the source-side lease cleanup path.
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

/// One terminal outcome for a staged native offer.
pub enum ReceiverDisposition {
    /// The receiver cloned and revalidated the expected directory.
    Ack(AcceptedDirectory),
    /// The offer was malformed, replayed, stale, or did not verify.
    Nack,
    /// The offer was consumed only after its bounded lifetime elapsed.
    Expired,
}

impl fmt::Debug for ReceiverDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiverDisposition(<redacted>)")
    }
}

/// Bounded, consume-once receiver state for one exact protected child process.
pub struct StagedHandleReceiver {
    binding: LauncherProcessBinding,
    capacity: usize,
    pending: BTreeMap<[u8; 16], PendingOffer>,
}

struct PendingOffer {
    borrowed_remote: HANDLE,
    expected_identity: DirectoryIdentity,
    expires_at: Instant,
}

impl StagedHandleReceiver {
    /// Creates a receiver bound to the current protected child process.
    ///
    /// # Errors
    ///
    /// Returns a closed error when binding does not name this process or capacity
    /// exceeds the bounded receiver limit.
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
        })
    }

    /// Stages a protected offer once, with its expiry measured on the receiver.
    ///
    /// # Errors
    ///
    /// Returns a closed error for mismatched child binding, duplicate offer ID,
    /// expired deadline arithmetic, or bounded-state exhaustion.
    pub fn stage(
        &mut self,
        offer: ProtectedHandleOffer,
        now: Instant,
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
            ttl,
            one_shot: _one_shot,
        } = ReceivedHandleOffer::decode(bytes)?;
        self.purge_expired(now);
        if binding != self.binding
            || self.pending.len() >= self.capacity
            || self.pending.contains_key(&offer_id)
        {
            return Err(NativeHandleError::Rejected);
        }
        let expires_at = now.checked_add(ttl).ok_or(NativeHandleError::Rejected)?;
        self.pending.insert(
            offer_id,
            PendingOffer {
                borrowed_remote,
                expected_identity,
                expires_at,
            },
        );
        Ok(())
    }

    /// Consumes, clones, and revalidates one offer without adopting its raw value.
    #[must_use]
    pub fn clone_received_and_verify(
        &mut self,
        offer_id: [u8; 16],
        now: Instant,
    ) -> ReceiverDisposition {
        let Some(received) = self.pending.remove(&offer_id) else {
            return ReceiverDisposition::Nack;
        };
        if now >= received.expires_at {
            return ReceiverDisposition::Expired;
        }
        let result = duplicate_local(received.borrowed_remote).and_then(|owned| {
            let directory = DirectoryHandle::from_owned(owned)?;
            (directory.identity() == received.expected_identity)
                .then_some(directory)
                .ok_or(NativeHandleError::Rejected)
        });
        result.map_or_else(
            |_| ReceiverDisposition::Nack,
            |directory| {
                ReceiverDisposition::Ack(AcceptedDirectory {
                    directory,
                    ack: HandleOfferAck(offer_id),
                })
            },
        )
    }

    fn purge_expired(&mut self, now: Instant) {
        self.pending.retain(|_, offer| offer.expires_at > now);
    }
}

impl fmt::Debug for StagedHandleReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagedHandleReceiver(<redacted>)")
    }
}
