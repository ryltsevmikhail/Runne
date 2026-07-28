//! Bootstrap v2-only direction-bound acknowledgement artifact.

use crate::cbor::{CborDecoder, CborEncoder, DecodeError, DeterministicCodec, EncodeError};
use crate::digest::ProfileDigest;
use crate::id::{Nonce, ProfileId, ProtocolSessionId};

/// Direction-bound acknowledgement in the bootstrap-v2 profile domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionAcknowledgedV2 {
    pub host_nonce: Nonce,
    pub plugin_nonce: Nonce,
    pub session_id: ProtocolSessionId,
    pub profile_id: ProfileId,
    pub profile_digest: ProfileDigest,
}

impl DeterministicCodec for SelectionAcknowledgedV2 {
    const MESSAGE_TYPE_ID: u32 = 2;

    fn encode(&self, enc: &mut CborEncoder) -> Result<(), EncodeError> {
        enc.write_map_header(6);
        enc.write_unsigned(1);
        enc.write_byte_string(self.host_nonce.as_bytes());
        enc.write_unsigned(2);
        enc.write_byte_string(self.plugin_nonce.as_bytes());
        enc.write_unsigned(3);
        enc.write_byte_string(self.session_id.as_bytes());
        enc.write_unsigned(4);
        enc.write_text_string(self.profile_id.as_str());
        enc.write_unsigned(5);
        enc.write_byte_string(self.profile_digest.as_bytes());
        // This literal is a v2 direction discriminator, not caller input.
        enc.write_unsigned(6);
        enc.write_unsigned(2);
        Ok(())
    }

    fn decode(_type_id: u32, dec: &mut CborDecoder) -> Result<Self, DecodeError> {
        if dec.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id: 2 });
        }
        expect_key(dec, 1)?;
        let host_nonce = decode_fixed::<16>(dec)?;
        expect_key(dec, 2)?;
        let plugin_nonce = decode_fixed::<16>(dec)?;
        expect_key(dec, 3)?;
        let session_id = decode_fixed::<16>(dec)?;
        // Preserve the protocol's UUID validation rather than accepting arbitrary bytes.
        if session_id[6] >> 4 != 7 || session_id[8] >> 6 != 0b10 {
            return Err(DecodeError::InvalidUuidVariant { offset: 0 });
        }
        expect_key(dec, 4)?;
        let profile_id = ProfileId::new(dec.read_text_string(128)?)
            .map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })?;
        expect_key(dec, 5)?;
        let profile_digest = decode_fixed::<32>(dec)?;
        expect_key(dec, 6)?;
        if dec.read_unsigned(6)? != 2 {
            return Err(DecodeError::UnknownField { key: 6 });
        }
        Ok(Self {
            host_nonce: Nonce::from_bytes(host_nonce),
            plugin_nonce: Nonce::from_bytes(plugin_nonce),
            session_id: ProtocolSessionId::from_bytes(session_id),
            profile_id,
            profile_digest: ProfileDigest::from_bytes(profile_digest),
        })
    }
}

fn expect_key(dec: &mut CborDecoder, expected: u64) -> Result<(), DecodeError> {
    let actual = dec.read_unsigned(6)?;
    if actual == expected {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key: actual })
    }
}

fn decode_fixed<const N: usize>(dec: &mut CborDecoder) -> Result<[u8; N], DecodeError> {
    let bytes = dec.read_byte_string(N)?;
    if bytes.len() != N {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    Ok(value)
}
