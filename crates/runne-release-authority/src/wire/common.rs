use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{AuthorityError, Digest};

pub(super) const fn safe_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

pub(super) fn identifier(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(safe_id_byte) {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}

pub(super) fn destination(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| safe_id_byte(byte) || matches!(byte, b':' | b'/'))
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}

pub(super) fn unique(values: &[String]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).all(|pair| pair[0] != pair[1])
}

pub(super) fn digest(value: &str) -> Result<Digest, AuthorityError> {
    let mut bytes = [0_u8; 32];
    if value.len() != 64 {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(Digest::from_bytes(bytes))
}

const fn nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::NonCanonicalPayload),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HexDigest(pub(super) Digest);
impl HexDigest {
    #[cfg(any(test, feature = "fixture-only"))]
    pub(crate) const fn value(self) -> Digest {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HexSignature(pub(super) [u8; 64]);

impl<'de> Deserialize<'de> for HexDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        digest(&value).map(Self).map_err(D::Error::custom)
    }
}

impl Serialize for HexDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_hex())
    }
}

impl<'de> Deserialize<'de> for HexSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 128 {
            return Err(D::Error::custom("invalid signature"));
        }
        let mut bytes = [0_u8; 64];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0]).map_err(D::Error::custom)? << 4)
                | nibble(pair[1]).map_err(D::Error::custom)?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for HexSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use std::fmt::Write as _;

        let value = self
            .0
            .iter()
            .fold(String::with_capacity(128), |mut output, byte| {
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
                output
            });
        serializer.serialize_str(&value)
    }
}
