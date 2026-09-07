//! Strict canonicalization: duplicate-key scan, V1 number bounds, JCS
//! rewrite equality. `serde_json` alone cannot reject duplicate keys, so
//! a bounded structural scanner walks the raw bytes first.

use crate::error::ManifestError;
use serde_json::Value;

/// Largest JSON integer permitted in a V1 manifest (2^53 - 1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_DEPTH: usize = 32;

pub struct Canonicalized {
    pub value: Value,
    pub canonical: String,
}

pub fn canonicalize_strict(bytes: &[u8]) -> Result<Canonicalized, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::InvalidUtf8)?;
    scan_duplicate_keys(text)?;
    let value: Value = serde_json::from_slice(bytes)?;
    check_numbers(&value)?;
    let canonical = serde_json_canonicalizer::to_string(&value)?;
    if text.trim_end() != canonical {
        return Err(ManifestError::NonCanonical);
    }
    Ok(Canonicalized { value, canonical })
}

fn check_numbers(value: &Value) -> Result<(), ManifestError> {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(ManifestError::Number(format!("{u} exceeds 2^53-1")));
                }
                Ok(())
            } else {
                Err(ManifestError::Number(format!("{n} is negative or float")))
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_numbers),
        Value::Object(map) => map.values().try_for_each(check_numbers),
        _ => Ok(()),
    }
}

/// Recursive scanner: records every object key (decoded) per level and
/// skips over values; syntactic errors inside strings are surfaced by the
/// serde_json parse that follows, so the scanner may be length-strict but
/// must never accept a duplicate that serde would fold.
fn scan_duplicate_keys(text: &str) -> Result<(), ManifestError> {
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    skip_ws(bytes, &mut pos);
    scan_value(bytes, &mut pos, 0)?;
    Ok(())
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && matches!(bytes[*pos], b' ' | b'\t' | b'\n' | b'\r') {
        *pos += 1;
    }
}

fn scan_value(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<(), ManifestError> {
    if depth > MAX_DEPTH {
        return Err(ManifestError::Number("nesting depth exceeds 32".into()));
    }
    skip_ws(bytes, pos);
    match bytes.get(*pos) {
        Some(b'{') => scan_object(bytes, pos, depth),
        Some(b'[') => scan_array(bytes, pos, depth),
        Some(b'"') => scan_string(bytes, pos).map(|_| ()),
        Some(_) => skip_literal(bytes, pos),
        None => Err(ManifestError::Json("unexpected end of input".into())),
    }
}

fn scan_object(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<(), ManifestError> {
    *pos += 1; // '{'
    let mut keys = std::collections::BTreeSet::new();
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b'}') {
        *pos += 1;
        return Ok(());
    }
    loop {
        skip_ws(bytes, pos);
        let key = scan_string(bytes, pos)?;
        if !keys.insert(key) {
            let at = *pos;
            return Err(ManifestError::DuplicateKey(at));
        }
        skip_ws(bytes, pos);
        match bytes.get(*pos) {
            Some(&b':') => *pos += 1,
            _ => {
                let at = *pos;
                let ctx = String::from_utf8_lossy(
                    &bytes[at.saturating_sub(24)..(at + 16).min(bytes.len())],
                );
                return Err(ManifestError::Json(format!(
                    "expected ':' in object at byte {at}: {ctx:?}"
                )));
            }
        }
        scan_value(bytes, pos, depth + 1)?;
        skip_ws(bytes, pos);
        match bytes.get(*pos) {
            Some(&b',') => *pos += 1,
            Some(&b'}') => {
                *pos += 1;
                return Ok(());
            }
            _ => return Err(ManifestError::Json("expected ',' or '}' in object".into())),
        }
    }
}

fn scan_array(bytes: &[u8], pos: &mut usize, depth: usize) -> Result<(), ManifestError> {
    *pos += 1; // '['
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b']') {
        *pos += 1;
        return Ok(());
    }
    loop {
        scan_value(bytes, pos, depth + 1)?;
        skip_ws(bytes, pos);
        match bytes.get(*pos) {
            Some(&b',') => *pos += 1,
            Some(&b']') => {
                *pos += 1;
                return Ok(());
            }
            _ => return Err(ManifestError::Json("expected ',' or ']' in array".into())),
        }
    }
}

/// Reads a JSON string starting at `"` returning the decoded key bytes.
fn scan_string(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, ManifestError> {
    if bytes.get(*pos) != Some(&b'"') {
        return Err(ManifestError::Json("expected string".into()));
    }
    *pos += 1;
    let mut out = Vec::new();
    loop {
        match bytes.get(*pos) {
            None => return Err(ManifestError::Json("unterminated string".into())),
            Some(b'"') => {
                *pos += 1;
                return Ok(out);
            }
            Some(b'\\') => {
                *pos += 1;
                let esc = bytes
                    .get(*pos)
                    .copied()
                    .ok_or_else(|| ManifestError::Json("unterminated escape".into()))?;
                *pos += 1;
                match esc {
                    b'"' | b'\\' | b'/' => out.push(esc),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'u' => {
                        let hex = bytes
                            .get(*pos..*pos + 4)
                            .ok_or_else(|| ManifestError::Json("bad \\u".into()))?;
                        let code = u32::from_str_radix(
                            std::str::from_utf8(hex)
                                .map_err(|_| ManifestError::Json("bad \\u".into()))?,
                            16,
                        )
                        .map_err(|_| ManifestError::Json("bad \\u".into()))?;
                        // Encode the code point minimally (surrogates kept
                        // as-is; serde rejects invalid combinations later).
                        push_utf8(&mut out, code);
                        *pos += 4;
                    }
                    other => out.push(other),
                }
            }
            Some(&b) => {
                out.push(b);
                *pos += 1;
            }
        }
    }
}

fn push_utf8(out: &mut Vec<u8>, code: u32) {
    match char::from_u32(code) {
        Some(c) => {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        None => out.extend_from_slice(format!("\\u{code:04x}").as_bytes()),
    }
}

fn skip_literal(bytes: &[u8], pos: &mut usize) -> Result<(), ManifestError> {
    while *pos < bytes.len()
        && !matches!(
            bytes[*pos],
            b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r'
        )
    {
        *pos += 1;
    }
    Ok(())
}
