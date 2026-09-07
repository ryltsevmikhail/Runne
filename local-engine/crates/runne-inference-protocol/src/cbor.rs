//! Deterministic CBOR (RFC 8949 core deterministic encoding):
//! minimal-length integers, bytewise-sorted map keys, fixed-length
//! rejection, duplicate-key rejection, re-encode equality.

use crate::error::ProtocolError;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(BTreeMap<Vec<u8>, Cbor>),
    Bool(bool),
    Null,
}

pub fn encode(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Unsigned(u) => head(out, 0, *u),
        Cbor::Negative(n) => head(out, 1, (-1 - *n) as u64),
        Cbor::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Cbor::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode(item, out);
            }
        }
        Cbor::Map(map) => {
            head(out, 5, map.len() as u64);
            // Deterministic: sort by encoded key bytes.
            let mut keys: Vec<(&Vec<u8>, &Cbor)> = map.iter().collect();
            keys.sort_by_key(|(k, _)| encoded_key(k));
            for (k, v) in keys {
                head(out, 3, k.len() as u64);
                out.extend_from_slice(k);
                encode(v, out);
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xF5 } else { 0xF4 }),
        Cbor::Null => out.push(0xF6),
    }
}

fn encoded_key(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 9);
    head(&mut out, 3, raw.len() as u64);
    out.extend_from_slice(raw);
    out
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    match value {
        0..=23 => out.push(m | value as u8),
        24..=0xFF => out.extend_from_slice(&[m | 24, value as u8]),
        0x100..=0xFFFF => out.extend_from_slice(&[m | 25, (value >> 8) as u8, value as u8]),
        0x1_0000..=0xFFFF_FFFF => out.extend_from_slice(&[
            m | 26,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]),
        _ => out.extend_from_slice(&[
            m | 27,
            (value >> 56) as u8,
            (value >> 48) as u8,
            (value >> 40) as u8,
            (value >> 32) as u8,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]),
    }
}

pub fn decode(bytes: &[u8]) -> Result<Cbor, ProtocolError> {
    let (value, used) = decode_inner(bytes, 0)?;
    if used != bytes.len() {
        return Err(ProtocolError::TrailingBytes);
    }
    Ok(value)
}

fn decode_inner(bytes: &[u8], start: usize) -> Result<(Cbor, usize), ProtocolError> {
    let (major, arg, head_len) = read_head(bytes, start)?;
    let mut pos = start + head_len;
    let value = match (major, arg) {
        (0, v) => Cbor::Unsigned(v),
        (1, v) => {
            let n = -1i64 - v as i64;
            Cbor::Negative(n)
        }
        (2, len) => {
            let len = usize::try_from(len).map_err(|_| ProtocolError::Oversize)?;
            if bytes.len() < pos + len {
                return Err(ProtocolError::Truncated);
            }
            let b = bytes[pos..pos + len].to_vec();
            pos += len;
            Cbor::Bytes(b)
        }
        (3, len) => {
            let len = usize::try_from(len).map_err(|_| ProtocolError::Oversize)?;
            if bytes.len() < pos + len {
                return Err(ProtocolError::Truncated);
            }
            let s = std::str::from_utf8(&bytes[pos..pos + len])
                .map_err(|_| ProtocolError::Malformed)?
                .to_string();
            pos += len;
            Cbor::Text(s)
        }
        (4, len) => {
            let len = usize::try_from(len).map_err(|_| ProtocolError::Oversize)?;
            let mut items = Vec::with_capacity(len.min(1024));
            for _ in 0..len {
                let (item, used) = decode_inner(bytes, pos)?;
                pos = used;
                items.push(item);
            }
            Cbor::Array(items)
        }
        (5, len) => {
            let len = usize::try_from(len).map_err(|_| ProtocolError::Oversize)?;
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let (k, used) = decode_inner(bytes, pos)?;
                pos = used;
                let key = match k {
                    Cbor::Text(s) => s.into_bytes(),
                    Cbor::Bytes(b) => b,
                    _ => return Err(ProtocolError::Malformed),
                };
                if map.insert(key.clone(), Cbor::Null).is_some() {
                    return Err(ProtocolError::DuplicateKey);
                }
                let (v, used) = decode_inner(bytes, pos)?;
                pos = used;
                map.insert(key, v);
            }
            Cbor::Map(map)
        }
        (7, 20) => Cbor::Bool(false),
        (7, 21) => Cbor::Bool(true),
        (7, 22) => Cbor::Null,
        _ => return Err(ProtocolError::Malformed),
    };
    Ok((value, pos))
}

fn read_head(bytes: &[u8], pos: usize) -> Result<(u8, u64, usize), ProtocolError> {
    let first = *bytes.get(pos).ok_or(ProtocolError::Truncated)?;
    let major = first >> 5;
    let info = first & 0x1F;
    let (value, len) = match info {
        0..=23 => (info as u64, 1),
        24 => (
            *bytes.get(pos + 1).ok_or(ProtocolError::Truncated)? as u64,
            2,
        ),
        25 => {
            if bytes.len() < pos + 3 {
                return Err(ProtocolError::Truncated);
            }
            (
                u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as u64,
                3,
            )
        }
        26 => {
            if bytes.len() < pos + 5 {
                return Err(ProtocolError::Truncated);
            }
            (
                u32::from_be_bytes([
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                ]) as u64,
                5,
            )
        }
        27 => {
            if bytes.len() < pos + 9 {
                return Err(ProtocolError::Truncated);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[pos + 1..pos + 9]);
            (u64::from_be_bytes(b), 9)
        }
        _ => return Err(ProtocolError::Malformed),
    };
    // Deterministic form: no indefinite lengths, minimal-length heads only.
    if info >= 28
        || (24..=27).contains(&info) && value < 24
        || (info == 25 && value <= 0xFF)
        || (info == 26 && value <= 0xFFFF)
        || (info == 27 && value <= 0xFFFF_FFFF)
    {
        return Err(ProtocolError::NonCanonical);
    }
    Ok((major, value, len))
}
