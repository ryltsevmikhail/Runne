//! Byte-level codec helpers for the raw stage-envelope verifier.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::AuthorityError;

pub fn signature(value: Option<Value>) -> Result<[u8; 64], AuthorityError> {
    let Some(Value::String(value)) = value else {
        return Err(AuthorityError::InvalidStageEnvelope);
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorityError::InvalidReceiptSignature)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidReceiptSignature)
}

pub fn hex_array(
    object: &mut serde_json::Map<String, Value>,
    name: &str,
) -> Result<(), AuthorityError> {
    let Some(Value::String(value)) = object.get(name) else {
        return Err(AuthorityError::InvalidStageEnvelope);
    };
    let output = decode_hex(value)?;
    object.insert(
        name.into(),
        Value::Array(
            output
                .into_iter()
                .map(|item| Value::Number(item.into()))
                .collect(),
        ),
    );
    Ok(())
}

pub fn decode_hex(value: &str) -> Result<[u8; 32], AuthorityError> {
    if !crate::receipt_v4_validation::hex_digest(value) {
        return Err(AuthorityError::InvalidStageEnvelope);
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

const fn nibble(value: u8) -> Result<u8, AuthorityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityError::InvalidStageEnvelope),
    }
}
