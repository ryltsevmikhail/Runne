//! Session-level authenticated frame encode/decode: strict next-sequence
//! per direction, MAC over the canonical frame map without `mac`,
//! direction-tagged keys.

use crate::ProtocolBody;
use crate::auth::{Direction, SessionKeys, hmac};
use crate::cbor::{self, Cbor};
use crate::error::ProtocolError;
use crate::frame::{self, Frame, WIRE_VERSION};
use crate::message::MessageV1;

pub struct Session<B: ProtocolBody = MessageV1> {
    keys: SessionKeys,
    session_id: [u8; 16],
    generation: u64,
    local: Direction,
    max_frame: u32,
    next_send: u64,
    next_recv: u64,
    _catalog: std::marker::PhantomData<B>,
}

impl<B: ProtocolBody> Session<B> {
    pub fn new(
        keys: SessionKeys,
        session_id: [u8; 16],
        generation: u64,
        local: Direction,
        max_frame: u32,
    ) -> Self {
        Self {
            keys,
            session_id,
            generation,
            local,
            max_frame,
            next_send: 0,
            next_recv: 0,
            _catalog: std::marker::PhantomData,
        }
    }

    /// Encodes and MACs the next outbound frame (transport sequence is
    /// monotonic; `ready` is sequence zero).
    pub fn encode(&mut self, message: &B) -> Result<Vec<u8>, ProtocolError> {
        let seq = self.next_send;
        self.next_send += 1;
        self.encode_at(message, seq)
    }

    /// Encode at an exact sequence (used by handshake `ready` = seq 0 and
    /// by tests for gap/replay scenarios).
    pub fn encode_at(&mut self, message: &B, sequence: u64) -> Result<Vec<u8>, ProtocolError> {
        let outbound = self.outbound_direction();
        let body = message.encode_body();
        let core = [
            ("v".to_string(), Cbor::Unsigned(WIRE_VERSION)),
            ("t".to_string(), Cbor::Text(message.type_name().to_string())),
            ("id".to_string(), Cbor::Bytes(self.frame_id().to_vec())),
            ("sid".to_string(), Cbor::Bytes(self.session_id.to_vec())),
            ("gen".to_string(), Cbor::Unsigned(self.generation)),
            ("dir".to_string(), Cbor::Text(outbound.as_str().to_string())),
            ("seq".to_string(), Cbor::Unsigned(sequence)),
            ("body".to_string(), body),
        ];
        let preimage = frame::frame_to_map(&core);
        let mut encoded = Vec::new();
        cbor::encode(&preimage, &mut encoded);
        let mac = hmac(self.keys.key(outbound), &[&encoded]);
        frame::encode_frame(&core, &mac, self.max_frame)
    }

    /// Decodes one inbound frame at the expected next sequence; any gap,
    /// replay, reflection, MAC or identity mismatch closes the session
    /// (typed error, zero operation effect).
    pub fn decode(&mut self, bytes: &[u8]) -> Result<B, ProtocolError> {
        let expected = self.next_recv;
        self.decode_at(bytes, expected)?;
        self.next_recv += 1;
        // Re-decode at final state: cheap because decode_at validated the
        // MAC and shape already.
        self.decode_at(bytes, expected)
    }

    fn decode_at(&mut self, bytes: &[u8], expected: u64) -> Result<B, ProtocolError> {
        let inbound = self.inbound_direction();
        let (value, canonical) = frame::decode_frame(bytes, self.max_frame)?;
        if !canonical {
            return Err(ProtocolError::NonCanonical);
        }
        let (core_map, mac) = frame::split_mac(value)?;
        let get_u = |m: &Cbor, k: &str| -> Result<u64, ProtocolError> {
            let Cbor::Map(map) = m else {
                return Err(ProtocolError::Malformed);
            };
            match map.get(k.as_bytes()) {
                Some(Cbor::Unsigned(u)) => Ok(*u),
                _ => Err(ProtocolError::UnknownField),
            }
        };
        let get_b = |m: &Cbor, k: &str| -> Result<Vec<u8>, ProtocolError> {
            let Cbor::Map(map) = m else {
                return Err(ProtocolError::Malformed);
            };
            match map.get(k.as_bytes()) {
                Some(Cbor::Bytes(b)) => Ok(b.clone()),
                _ => Err(ProtocolError::UnknownField),
            }
        };
        let get_t = |m: &Cbor, k: &str| -> Result<String, ProtocolError> {
            let Cbor::Map(map) = m else {
                return Err(ProtocolError::Malformed);
            };
            match map.get(k.as_bytes()) {
                Some(Cbor::Text(s)) => Ok(s.clone()),
                _ => Err(ProtocolError::UnknownField),
            }
        };
        // Version + identity + direction binding.
        if get_u(&core_map, "v")? != WIRE_VERSION {
            return Err(ProtocolError::ProtocolMismatch);
        }
        if get_u(&core_map, "gen")? != self.generation {
            return Err(ProtocolError::IdentityMismatch);
        }
        if get_b(&core_map, "sid")? != self.session_id.to_vec() {
            return Err(ProtocolError::IdentityMismatch);
        }
        let dir = get_t(&core_map, "dir")?;
        if dir != inbound.as_str() {
            return Err(ProtocolError::Reflection);
        }
        let seq = get_u(&core_map, "seq")?;
        if seq != expected {
            // Includes byte-identical replay (expected already advanced).
            return Err(ProtocolError::SequenceGap);
        }
        // MAC over the canonical map without `mac`, under the direction key.
        let mut encoded = Vec::new();
        cbor::encode(&core_map, &mut encoded);
        let expected_mac = hmac(self.keys.key(inbound), &[&encoded]);
        if expected_mac != mac {
            return Err(ProtocolError::MacMismatch);
        }
        let t = get_t(&core_map, "t")?;
        let body = match core_map {
            Cbor::Map(map) => map
                .get(b"body".as_slice())
                .cloned()
                .ok_or(ProtocolError::UnknownField)?,
            _ => return Err(ProtocolError::Malformed),
        };
        B::decode_body(&t, &body)
    }

    fn frame_id(&self) -> [u8; 16] {
        // Deterministic frame id from identity + counters (bounded dedup
        // cache is unnecessary because strict seq rejects replays).
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.session_id[..8]);
        id[8..].copy_from_slice(&self.next_send.to_be_bytes());
        id
    }

    fn outbound_direction(&self) -> Direction {
        match self.local {
            Direction::C2h => Direction::C2h,
            Direction::H2c => Direction::H2c,
        }
    }

    fn inbound_direction(&self) -> Direction {
        match self.local {
            Direction::C2h => Direction::H2c,
            Direction::H2c => Direction::C2h,
        }
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

pub use crate::frame::{MAX_CONTROL_FRAME, MAX_REQUEST_FRAME, MAX_STREAM_ITEM_FRAME};
pub type FrameT = Frame;
