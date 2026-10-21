//! UTF8/depth envelope ONLY. serde remains the full JSON grammar authority.
use super::MetadataQueryError;
pub(super) fn check(bytes: &[u8]) -> Result<(), MetadataQueryError> {
    let invalid = MetadataQueryError::InvalidSnapshot;
    std::str::from_utf8(bytes).map_err(|_| invalid)?;
    let (mut string, mut escaped, mut depth) = (false, false, 0usize);
    for &b in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth = depth.checked_add(1).ok_or(invalid)?;
                    if depth > 64 {
                        return Err(invalid);
                    }
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or(invalid)?,
                _ => {}
            }
        }
    }
    if string || depth != 0 {
        return Err(invalid);
    }
    Ok(())
}
