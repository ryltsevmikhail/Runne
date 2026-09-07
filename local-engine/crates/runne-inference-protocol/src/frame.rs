//! Wire framing: `uint32_be(length) || deterministic-CBOR(frame map)` with
//! negotiated size bounds and canonical re-encode equality.

use crate::cbor::{self, Cbor};
use crate::error::ProtocolError;

/// Default protocol maxima (PROTOCOL.md §Canonical frame); negotiated
/// downward in `welcome` per session.
pub const MAX_CONTROL_FRAME: u32 = 64 * 1024;
pub const MAX_REQUEST_FRAME: u32 = 1024 * 1024;
pub const MAX_STREAM_ITEM_FRAME: u32 = 256 * 1024;

pub const WIRE_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub version: u64,
    pub msg_type: String,
    pub id: [u8; 16],
    pub session_id: [u8; 16],
    pub generation: u64,
    pub dir: String,
    pub sequence: u64,
    pub body: Cbor,
    pub mac: [u8; 32],
}

/// Encodes the canonical frame map (without `mac`) for signing/hashing.
pub fn frame_to_map(frame_core: &[(String, Cbor)]) -> Cbor {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in frame_core {
        map.insert(k.clone().into_bytes(), v.clone());
    }
    Cbor::Map(map)
}

pub fn encode_frame(
    core: &[(String, Cbor)],
    mac: &[u8; 32],
    max_frame: u32,
) -> Result<Vec<u8>, ProtocolError> {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in core {
        map.insert(k.clone().into_bytes(), v.clone());
    }
    map.insert(b"mac".to_vec(), Cbor::Bytes(mac.to_vec()));
    let mut payload = Vec::with_capacity(128);
    cbor::encode(&Cbor::Map(map), &mut payload);
    if payload.len() as u64 + 4 > max_frame as u64 {
        return Err(ProtocolError::Oversize);
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decodes and verifies canonical re-encode equality.
pub fn decode_frame(bytes: &[u8], max_frame: u32) -> Result<(Cbor, bool), ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::Truncated);
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len as u64 + 4 > max_frame as u64 {
        return Err(ProtocolError::Oversize);
    }
    if bytes.len() < 4 + len {
        return Err(ProtocolError::Truncated);
    }
    if bytes.len() > 4 + len {
        return Err(ProtocolError::TrailingBytes);
    }
    let value = cbor::decode(&bytes[4..])?;
    // Canonical re-encode equality: the decoded map must re-encode to the
    // exact same bytes.
    let mut reencoded = Vec::with_capacity(len);
    cbor::encode(&value, &mut reencoded);
    let canonical = reencoded == bytes[4..];
    Ok((value, canonical))
}

/// Extracts the `mac` member from a decoded frame map, removing it in
/// place (the remaining map is the MAC preimage).
pub fn split_mac(value: Cbor) -> Result<(Cbor, [u8; 32]), ProtocolError> {
    let Cbor::Map(mut map) = value else {
        return Err(ProtocolError::Malformed);
    };
    let mac_value = map
        .remove(b"mac".as_slice())
        .ok_or(ProtocolError::MacMismatch)?;
    let Cbor::Bytes(mac) = mac_value else {
        return Err(ProtocolError::MacMismatch);
    };
    let mac: [u8; 32] = mac.try_into().map_err(|_| ProtocolError::MacMismatch)?;
    Ok((Cbor::Map(map), mac))
}

/// Wraps an outer handshake map into a length-prefixed control frame.
pub fn pack_outer(map: Cbor, max_frame: u32) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    cbor::encode(&map, &mut payload);
    if payload.len() as u64 + 4 > max_frame as u64 {
        return Err(ProtocolError::Oversize);
    }
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}
