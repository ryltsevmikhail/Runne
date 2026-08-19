#![allow(clippy::redundant_pub_crate)]

use std::fmt;

use sha2::{Digest, Sha256};

use crate::protocol::ProtocolError;

pub(super) const OFFER_BYTES: usize = 104;
pub(super) const CONTROL_BYTES: usize = 64;
const OFFER_MAGIC: [u8; 4] = *b"GHO2";
const READY_MAGIC: [u8; 4] = *b"GHA2";
const FINALIZE_MAGIC: [u8; 4] = *b"GHF2";
const NACK_MAGIC: [u8; 4] = *b"GHN2";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct IdentityWire {
    pub(super) volume_serial: u64,
    pub(super) file_id: [u8; 16],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct OfferParts {
    pub(super) offer_id: [u8; 16],
    pub(super) target_pid: u32,
    pub(super) launch_generation: u64,
    pub(super) identity: IdentityWire,
    pub(super) deadline_millis: u64,
    pub(super) remote_token: u64,
    pub(super) transcript: [u8; 32],
}

/// Opaque, fixed-size protected-channel offer. It never exposes the remote
/// native token or a filesystem path.
pub struct ProtectedHandleOffer([u8; OFFER_BYTES]);

impl ProtectedHandleOffer {
    #[must_use]
    pub const fn into_protected_bytes(self) -> [u8; OFFER_BYTES] {
        self.0
    }

    /// # Errors
    ///
    /// Rejects a non-canonical frame before any time or handle operation.
    pub fn from_protected_bytes(bytes: [u8; OFFER_BYTES]) -> Result<Self, ProtocolError> {
        let _ = decode_offer(bytes)?;
        Ok(Self(bytes))
    }

    pub(super) fn parts(&self) -> Result<OfferParts, ProtocolError> {
        decode_offer(self.0)
    }
}

impl fmt::Debug for ProtectedHandleOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedHandleOffer(<redacted>)")
    }
}

/// Opaque fixed-size ready acknowledgement.
pub struct HandleAckReady([u8; CONTROL_BYTES]);
/// Opaque fixed-size sender finalization.
pub struct HandleFinalize([u8; CONTROL_BYTES]);
/// Opaque fixed-size rejection/cancellation frame.
pub struct HandleNack([u8; CONTROL_BYTES]);

macro_rules! protected_control {
    ($type_name:ident, $expected_kind:expr) => {
        impl $type_name {
            #[must_use]
            pub const fn into_protected_bytes(self) -> [u8; CONTROL_BYTES] {
                self.0
            }

            /// # Errors
            ///
            /// Rejects a frame with the wrong tag, transcript, or reserved bytes.
            pub fn from_protected_bytes(bytes: [u8; CONTROL_BYTES]) -> Result<Self, ProtocolError> {
                (decode_control(bytes)?.kind == $expected_kind)
                    .then_some(Self(bytes))
                    .ok_or(ProtocolError::Rejected)
            }

            #[allow(dead_code)]
            pub(super) fn parts(&self) -> Result<ControlParts, ProtocolError> {
                decode_control(self.0)
            }
        }

        impl fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($type_name), "(<redacted>)"))
            }
        }
    };
}

protected_control!(HandleAckReady, ControlKind::Ready);
protected_control!(HandleFinalize, ControlKind::Finalize);
protected_control!(HandleNack, ControlKind::Nack);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ControlKind {
    Ready,
    Finalize,
    Nack,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ControlParts {
    pub(super) kind: ControlKind,
    pub(super) offer_id: [u8; 16],
    pub(super) transcript: [u8; 32],
}

pub(super) fn encode_offer(parts: OfferParts) -> ProtectedHandleOffer {
    let mut bytes = [0; OFFER_BYTES];
    bytes[..4].copy_from_slice(&OFFER_MAGIC);
    bytes[4..20].copy_from_slice(&parts.offer_id);
    bytes[20..24].copy_from_slice(&parts.target_pid.to_be_bytes());
    bytes[24..32].copy_from_slice(&parts.launch_generation.to_be_bytes());
    bytes[32..40].copy_from_slice(&parts.identity.volume_serial.to_be_bytes());
    bytes[40..56].copy_from_slice(&parts.identity.file_id);
    bytes[56..64].copy_from_slice(&parts.deadline_millis.to_be_bytes());
    bytes[64..72].copy_from_slice(&parts.remote_token.to_be_bytes());
    let transcript = offer_transcript(&bytes[..72]);
    bytes[72..].copy_from_slice(&transcript);
    ProtectedHandleOffer(bytes)
}

pub(super) fn ready(parts: OfferParts) -> HandleAckReady {
    HandleAckReady(encode_control(
        ControlKind::Ready,
        parts.offer_id,
        parts.transcript,
    ))
}

pub(super) fn finalize(parts: OfferParts) -> HandleFinalize {
    HandleFinalize(encode_control(
        ControlKind::Finalize,
        parts.offer_id,
        parts.transcript,
    ))
}

pub(super) fn nack(parts: OfferParts) -> HandleNack {
    HandleNack(encode_control(
        ControlKind::Nack,
        parts.offer_id,
        parts.transcript,
    ))
}

fn decode_offer(bytes: [u8; OFFER_BYTES]) -> Result<OfferParts, ProtocolError> {
    if bytes[..4] != OFFER_MAGIC || bytes[72..] != offer_transcript(&bytes[..72]) {
        return Err(ProtocolError::Rejected);
    }
    let mut offer_id = [0; 16];
    offer_id.copy_from_slice(&bytes[4..20]);
    let mut file_id = [0; 16];
    file_id.copy_from_slice(&bytes[40..56]);
    let mut transcript = [0; 32];
    transcript.copy_from_slice(&bytes[72..]);
    let parts = OfferParts {
        offer_id,
        target_pid: u32::from_be_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| ProtocolError::Rejected)?,
        ),
        launch_generation: u64::from_be_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| ProtocolError::Rejected)?,
        ),
        identity: IdentityWire {
            volume_serial: u64::from_be_bytes(
                bytes[32..40]
                    .try_into()
                    .map_err(|_| ProtocolError::Rejected)?,
            ),
            file_id,
        },
        deadline_millis: u64::from_be_bytes(
            bytes[56..64]
                .try_into()
                .map_err(|_| ProtocolError::Rejected)?,
        ),
        remote_token: u64::from_be_bytes(
            bytes[64..72]
                .try_into()
                .map_err(|_| ProtocolError::Rejected)?,
        ),
        transcript,
    };
    (parts.offer_id != [0; 16]
        && parts.target_pid != 0
        && parts.launch_generation != 0
        && parts.identity.volume_serial != 0
        && parts.identity.file_id != [0; 16]
        && parts.remote_token != 0)
        .then_some(parts)
        .ok_or(ProtocolError::Rejected)
}

fn encode_control(
    kind: ControlKind,
    offer_id: [u8; 16],
    transcript: [u8; 32],
) -> [u8; CONTROL_BYTES] {
    let mut bytes = [0; CONTROL_BYTES];
    bytes[..4].copy_from_slice(magic(kind));
    bytes[4..20].copy_from_slice(&offer_id);
    bytes[20..52].copy_from_slice(&transcript);
    bytes
}

fn decode_control(bytes: [u8; CONTROL_BYTES]) -> Result<ControlParts, ProtocolError> {
    let kind = if bytes[..4] == READY_MAGIC {
        ControlKind::Ready
    } else if bytes[..4] == FINALIZE_MAGIC {
        ControlKind::Finalize
    } else if bytes[..4] == NACK_MAGIC {
        ControlKind::Nack
    } else {
        return Err(ProtocolError::Rejected);
    };
    if bytes[52..] != [0; 12] {
        return Err(ProtocolError::Rejected);
    }
    let mut offer_id = [0; 16];
    offer_id.copy_from_slice(&bytes[4..20]);
    let mut transcript = [0; 32];
    transcript.copy_from_slice(&bytes[20..52]);
    (offer_id != [0; 16] && transcript != [0; 32])
        .then_some(ControlParts {
            kind,
            offer_id,
            transcript,
        })
        .ok_or(ProtocolError::Rejected)
}

pub(super) fn decode_control_for_receiver(
    bytes: [u8; CONTROL_BYTES],
) -> Result<ControlParts, ProtocolError> {
    decode_control(bytes)
}

pub(super) fn nack_from_control(control: ControlParts) -> HandleNack {
    HandleNack(encode_control(
        ControlKind::Nack,
        control.offer_id,
        control.transcript,
    ))
}

const fn magic(kind: ControlKind) -> &'static [u8; 4] {
    match kind {
        ControlKind::Ready => &READY_MAGIC,
        ControlKind::Finalize => &FINALIZE_MAGIC,
        ControlKind::Nack => &NACK_MAGIC,
    }
}

fn offer_transcript(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"runne.root-handle-offer.v2");
    hasher.update(bytes);
    hasher.finalize().into()
}
