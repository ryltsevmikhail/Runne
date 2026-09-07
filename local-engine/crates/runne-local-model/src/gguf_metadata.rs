//! Bounded GGUF metadata-value reader.

use crate::error::ManifestError;
use crate::gguf::{CapturedValue, Reader};
use crate::gguf_limits::*;

pub(crate) fn read_metadata_value(
    reader: &mut Reader<'_>,
    depth: usize,
    key: &str,
) -> Result<Option<CapturedValue>, ManifestError> {
    let raw_type = reader.u32()?;
    let value_type = value_type(raw_type).ok_or_else(|| {
        ManifestError::Schema(format!("gguf: unsupported metadata value type {raw_type}"))
    })?;
    match value_type {
        GgufValueType::String => capture_string(reader.string()?, key),
        GgufValueType::Array => skip_array(reader, depth, key),
        GgufValueType::U32 => {
            let value = u32::from_le_bytes(
                reader
                    .take(4)?
                    .try_into()
                    .map_err(|_| ManifestError::Schema("gguf: bad u32".into()))?,
            );
            Ok(capture_u64(key, u64::from(value)))
        }
        GgufValueType::U64 => Ok(capture_u64(key, reader.u64()?)),
        other => {
            reader.take(scalar_width(other).expect("non-string/array has width"))?;
            Ok(None)
        }
    }
}

fn capture_string(value: String, key: &str) -> Result<Option<CapturedValue>, ManifestError> {
    if key == "tokenizer.ggml.model" || key == "general.architecture" {
        if value.len() as u64 > MAX_ID_STRING_BYTES {
            return Err(ManifestError::Number(format!(
                "gguf id string too long: {}",
                value.len()
            )));
        }
        return Ok(Some(CapturedValue::Text(value)));
    }
    if key == "tokenizer.chat_template" {
        if value.len() as u64 > MAX_TEMPLATE_BYTES {
            return Err(ManifestError::Number(format!(
                "gguf: embedded template too large: {}",
                value.len()
            )));
        }
        return Ok(Some(CapturedValue::Text(value)));
    }
    Ok(None)
}

fn skip_array(
    reader: &mut Reader<'_>,
    depth: usize,
    key: &str,
) -> Result<Option<CapturedValue>, ManifestError> {
    if depth >= MAX_ARRAY_DEPTH {
        return Err(ManifestError::Schema("gguf: array nesting too deep".into()));
    }
    let raw_type = reader.u32()?;
    let element_type = value_type(raw_type).ok_or_else(|| {
        ManifestError::Schema(format!("gguf: unsupported array element type {raw_type}"))
    })?;
    let length = reader.u64()?;
    if length > MAX_ARRAY_LEN {
        return Err(ManifestError::Number(format!(
            "gguf array too long: {length}"
        )));
    }
    if let Some(width) = scalar_width(element_type) {
        reader.take(
            length
                .checked_mul(width)
                .ok_or_else(|| ManifestError::Number("gguf array size overflow".into()))?,
        )?;
    } else {
        for _ in 0..length {
            match element_type {
                GgufValueType::String => {
                    reader.string()?;
                }
                GgufValueType::Array => {
                    read_metadata_value(reader, depth + 1, key)?;
                }
                _ => unreachable!("scalar widths handled above"),
            }
        }
    }
    Ok(None)
}

fn capture_u64(key: &str, value: u64) -> Option<CapturedValue> {
    key.ends_with(".context_length")
        .then_some(CapturedValue::U64(value))
}
