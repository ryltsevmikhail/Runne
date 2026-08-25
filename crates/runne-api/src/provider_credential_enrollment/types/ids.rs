use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque 128-bit durable operation identity used only for authenticated resume.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProviderCredentialOperationIdV2([u8; 16]);

impl ProviderCredentialOperationIdV2 {
    /// Creates a non-zero operation identity from authoritative bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, &'static str> {
        if bytes == [0; 16] {
            Err("provider credential operation identity is zero")
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the opaque identity bytes for daemon translation.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Serialize for ProviderCredentialOperationIdV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(self.0))
    }
}

impl<'de> Deserialize<'de> for ProviderCredentialOperationIdV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        decode_hex(&value)
            .and_then(Self::from_bytes)
            .map_err(serde::de::Error::custom)
    }
}

fn decode_hex(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid provider credential operation identity");
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(bytes)
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn encode_hex(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
